"""Strict URI conversion: unsupported features never silently disappear."""
import base64
import hashlib
import json
import uuid
from urllib.parse import parse_qs, unquote, urlsplit


class ProfileError(ValueError):
    pass


def decode64(value):
    value = ''.join(value.split())
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8')


def parse_uri(uri):
    p = urlsplit(uri)
    if p.scheme not in ('vless', 'trojan'):
        raise ProfileError('Supported URI protocols: vless, trojan')
    if not p.hostname or not p.port or not p.username or p.password:
        raise ProfileError('Missing or invalid server, port or credentials')
    q = parse_qs(p.query, keep_blank_values=True)
    allowed = {'type', 'security', 'encryption', 'flow', 'fp', 'pbk', 'sid', 'sni', 'spx',
               'alpn', 'allowInsecure', 'insecure', 'path', 'host', 'serviceName', 'headerType'}
    if set(q) - allowed:
        raise ProfileError('Unsupported connection parameters')
    if any(len(v) != 1 for v in q.values()):
        raise ProfileError('Duplicate connection parameters')
    get = lambda k, default='': q.get(k, [default])[0]
    transport = get('type', 'tcp')
    if transport not in ('tcp', 'raw', 'ws', 'grpc', 'http', 'h2', 'httpupgrade'):
        raise ProfileError('Unsupported transport (including XHTTP); use an Xray-compatible transport')
    if get('encryption', 'none') != 'none' or get('headerType', 'none') != 'none':
        raise ProfileError('Unsupported encryption or TCP header obfuscation')
    out = {'type': p.scheme, 'server': p.hostname, 'server_port': p.port}
    if p.scheme == 'vless':
        try:
            out['uuid'] = str(uuid.UUID(unquote(p.username)))
        except ValueError:
            raise ProfileError('Invalid VLESS UUID') from None
        flow = get('flow')
        if flow not in ('', 'xtls-rprx-vision'):
            raise ProfileError('Unsupported VLESS flow')
        if flow:
            if transport not in ('tcp', 'raw'):
                raise ProfileError('Vision requires TCP')
            out['flow'] = flow
    else:
        out['password'] = unquote(p.username)
    security = get('security', 'tls' if p.scheme == 'trojan' else 'none')
    if security not in ('none', 'tls', 'reality'):
        raise ProfileError('Unsupported TLS security')
    if security != 'none':
        tls = {'enabled': True, 'server_name': get('sni', p.hostname)}
        if get('allowInsecure', get('insecure', '0')) not in ('0', 'false', ''):
            raise ProfileError('Insecure TLS is not accepted')
        if get('alpn'):
            tls['alpn'] = get('alpn').split(',')
        if get('fp') or security == 'reality':
            tls['utls'] = {'enabled': True, 'fingerprint': get('fp', 'chrome')}
        if security == 'reality':
            if not get('pbk'):
                raise ProfileError('Reality public key is required')
            tls['reality'] = {'enabled': True, 'public_key': get('pbk'), 'short_id': get('sid')}
        out['tls'] = tls
    elif get('flow'):
        raise ProfileError('Vision requires TLS/Reality')
    if transport not in ('tcp', 'raw'):
        tr = {'type': 'http' if transport == 'h2' else transport}
        if transport == 'grpc':
            tr['service_name'] = get('serviceName')
        else:
            tr['path'] = get('path', '/')
            if get('host'):
                if transport in ('h2', 'http'):
                    tr['host'] = get('host').split(',')
                elif transport == 'httpupgrade':
                    tr['host'] = get('host')
                else:
                    tr['headers'] = {'Host': get('host')}
        out['transport'] = tr
    # Xray's spiderX is not a sing-box transport field; it does not change the connection.
    identity = hashlib.sha256(json.dumps(out, sort_keys=True).encode()).hexdigest()[:16]
    return {'id': identity, 'name': unquote(p.fragment) or p.scheme.upper(), 'outbound': out}


def parse_subscription(body):
    if len(body) > 2_000_000:
        raise ProfileError('Subscription exceeds 2 MB')
    text = body.decode('utf-8-sig').strip()
    if not text.startswith(('vless://', 'trojan://')):
        try:
            text = decode64(text)
        except (ValueError, UnicodeError):
            raise ProfileError('Expected plain or Base64 URI subscription') from None
    nodes = {}
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            node = parse_uri(line.strip())
        except (ValueError, UnicodeError):
            raise ProfileError(f'Unsupported or invalid subscription entry #{index}; cache preserved') from None
        nodes[node['id']] = node
    if not nodes:
        raise ProfileError('Empty subscription; cache preserved')
    return list(nodes.values())
