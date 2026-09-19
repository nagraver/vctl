"""Xray configuration; stored node IDs remain compatible with existing profiles."""
import ipaddress

FIELDS = {'domain': 'domain', 'suffix': 'domain', 'cidr': 'ip'}
PRIVATE = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','::1/128','fc00::/7','fe80::/10']


def make_rule(kind, value, action):
    if kind in ('process', 'path'):
        raise ValueError('Xray does not support process/path routing on macOS; use domain, suffix or cidr')
    if action not in ('direct', 'proxy', 'block') or kind not in FIELDS:
        raise ValueError('Invalid routing rule')
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid rule value')
    if kind == 'cidr':
        value = str(ipaddress.ip_network(value, strict=False))
    return {'kind': kind, 'value': value, 'action': action}


def outbound(node):
    o = node['outbound']
    if o['type'] == 'vless':
        user = {'id': o['uuid'], 'encryption': 'none'}
        if o.get('flow'): user['flow'] = o['flow']
        settings = {'vnext': [{'address': o['server'], 'port': o['server_port'], 'users': [user]}]}
    elif o['type'] == 'trojan':
        settings = {'servers': [{'address': o['server'], 'port': o['server_port'], 'password': o['password']}]}
    else:
        raise ValueError('Unsupported outbound protocol')
    stream = {'network': 'tcp', 'security': 'none'}
    tls = o.get('tls', {})
    if tls.get('enabled'):
        security = 'reality' if tls.get('reality', {}).get('enabled') else 'tls'
        stream['security'] = security
        fields = {'serverName': tls.get('server_name', o['server'])}
        if tls.get('utls', {}).get('enabled'): fields['fingerprint'] = tls['utls']['fingerprint']
        if security == 'reality':
            fields.update(password=tls['reality']['public_key'], shortId=tls['reality'].get('short_id', ''))
            fields.setdefault('fingerprint', 'chrome')
        elif tls.get('alpn'): fields['alpn'] = tls['alpn']
        stream[security + 'Settings'] = fields
    tr = o.get('transport', {})
    kind = tr.get('type')
    if kind == 'ws':
        stream.update(network='ws', wsSettings={'path': tr.get('path', '/'), 'headers': tr.get('headers', {})})
    elif kind == 'grpc':
        stream.update(network='grpc', grpcSettings={'serviceName': tr.get('service_name', '')})
    elif kind == 'httpupgrade':
        stream.update(network='httpupgrade', httpupgradeSettings={'path': tr.get('path', '/'), 'host': tr.get('host', '')})
    elif kind:
        raise ValueError('Stored transport is not supported by this Xray adapter; cache preserved')
    return {'protocol': o['type'], 'tag': 'node-' + node['id'], 'settings': settings, 'streamSettings': stream}


def generate(state, mode='proxy', port=2080):
    if mode not in ('proxy', 'tun') or not 1 <= port <= 65534:
        raise ValueError('Invalid mode or port (use 1..65534; HTTP uses port+1)')
    nodes = {n['id']: n for sub in state['subscriptions'].values() for n in sub['nodes']}
    if not nodes: raise ValueError('Add a subscription first')
    chosen = state.get('selected', 'auto')
    if chosen != 'auto' and chosen not in nodes:
        raise ValueError('Selected node disappeared; select a node or auto explicitly')
    tags = ['node-' + i for i in nodes]
    def target(action):
        if action == 'proxy':
            return {'balancerTag': 'auto'} if chosen == 'auto' else {'outboundTag': 'node-' + chosen}
        return {'outboundTag': action}
    rules = [{'type': 'field', 'inboundTag': ['dns-query'], **target(state['default'])},
             {'type': 'field', 'port': '53', 'outboundTag': 'dns-out'}]
    direct_domains = []
    for raw in state['rules']:
        r = make_rule(**raw); value = r['value']
        if r['kind'] in ('domain', 'suffix'):
            value = ('full:' if r['kind'] == 'domain' else 'domain:') + value
            if r['action'] == 'direct': direct_domains.append(value)
        rules.append({'type': 'field', FIELDS[r['kind']]: [value], **target(r['action'])})
    rules.extend([{'type': 'field', 'ip': PRIVATE, 'outboundTag': 'direct'},
                  {'type': 'field', 'network': 'tcp,udp', **target(state['default'])}])
    sniff = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    inbounds = [{'tag': 'socks-in', 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                 'settings': {'auth': 'noauth', 'udp': True}, 'sniffing': sniff},
                {'tag': 'http-in', 'listen': '127.0.0.1', 'port': port + 1, 'protocol': 'http',
                 'settings': {}, 'sniffing': sniff}]
    if mode == 'tun':
        inbounds.append({'tag': 'tun-in', 'protocol': 'tun', 'settings': {
            'mtu': 1500, 'gateway': ['172.28.0.1/30'],
            'autoSystemRoutingTable': ['0.0.0.0/0', '::/0'], 'autoOutboundsInterface': 'auto'},
            'sniffing': sniff})
    dns_servers = []
    if direct_domains:
        dns_servers.append({'address': 'https+local://1.1.1.1/dns-query', 'domains': direct_domains, 'skipFallback': True})
    dns_servers.append('https://1.1.1.1/dns-query' if state['default'] == 'proxy' else 'https+local://1.1.1.1/dns-query')
    config = {'log': {'loglevel': 'warning'}, 'inbounds': inbounds,
              'dns': {'servers': dns_servers, 'tag': 'dns-query', 'queryStrategy': 'UseIP'},
              'outbounds': [outbound(n) for n in nodes.values()] + [
                  {'protocol': 'freedom', 'tag': 'direct', 'settings': {'domainStrategy': 'UseIP'}},
                  {'protocol': 'blackhole', 'tag': 'block', 'settings': {}},
                  {'protocol': 'dns', 'tag': 'dns-out', 'settings': {}}],
              'routing': {'domainStrategy': 'IPOnDemand', 'rules': rules}}
    if chosen == 'auto':
        config['routing']['balancers'] = [{'tag': 'auto', 'selector': tags,
                                           'fallbackTag': tags[0], 'strategy': {'type': 'leastPing'}}]
        config['observatory'] = {'subjectSelector': tags, 'probeURL': state['test_url'],
                                 'probeInterval': '5m', 'enableConcurrency': True}
    return config
