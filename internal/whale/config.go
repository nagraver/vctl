package whale

import (
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

var privateIPs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}
var ruleFields = map[string]string{"domain": "domain", "suffix": "domain", "cidr": "ip", "geoip": "ip", "geosite": "domain", "process": "process", "path": "process"}

func MakeRule(kind, value, action string) (Rule, error) {
	r := Rule{kind, value, action}
	if ruleFields[kind] == "" || action != "direct" && action != "proxy" && action != "block" || value == "" || strings.ContainsAny(value, "\n\r\x00\x1b") {
		return r, errors.New("invalid routing rule")
	}
	for _, char := range value {
		if char < 32 {
			return r, errors.New("invalid rule value")
		}
	}
	switch kind {
	case "cidr":
		p, e := netip.ParsePrefix(value)
		if e != nil {
			if ip, err := netip.ParseAddr(value); err == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
				e = nil
			}
		}
		if e != nil {
			return r, errors.New("invalid CIDR")
		}
		value = p.Masked().String()
	case "domain", "suffix":
		var e error
		value, e = idna.Lookup.ToASCII(strings.ToLower(strings.TrimRight(value, ".")))
		if e != nil || len(value) > 253 {
			return r, errors.New("invalid hostname")
		}
		for _, part := range strings.Split(value, ".") {
			if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(part) {
				return r, errors.New("use a hostname without scheme, wildcard or path")
			}
		}
	case "geoip", "geosite":
		value = strings.ToLower(value)
		if !regexp.MustCompile(`^[a-z0-9_!-]+(?:@[a-z0-9_!-]+)?$`).MatchString(value) {
			return r, errors.New("invalid geodata category")
		}
	case "process":
		if strings.Contains(value, "/") {
			return r, errors.New("use path for an absolute executable")
		}
	case "path":
		if !filepath.IsAbs(value) {
			return r, errors.New("application path must be absolute")
		}
		trail := strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".app")
		value = filepath.Clean(value)
		if trail {
			value += "/"
		}
	}
	r.Value = value
	return r, nil
}
func effectiveRules(s State) ([]Rule, error) {
	out := append([]Rule{}, s.Rules...)
	for _, k := range s.Presets.Keys {
		p := s.Presets.Values[k]
		if p.Enabled {
			out = append(out, p.Rules...)
		}
	}
	for i, r := range out {
		v, e := MakeRule(r.Kind, r.Value, r.Action)
		if e != nil {
			return nil, e
		}
		out[i] = v
	}
	return out, nil
}
func Outbound(n Node) (M, error) {
	o := n.Outbound
	settings := M{}
	switch str(o, "type") {
	case "vless":
		user := M{"id": o["uuid"], "encryption": "none"}
		if str(o, "flow") != "" {
			user["flow"] = o["flow"]
		}
		settings["vnext"] = []M{{"address": o["server"], "port": o["server_port"], "users": []M{user}}}
	case "trojan":
		settings["servers"] = []M{{"address": o["server"], "port": o["server_port"], "password": o["password"]}}
	default:
		return nil, errors.New("unsupported outbound protocol")
	}
	stream := M{"network": "tcp", "security": "none"}
	if m, ok := o["finalmask"]; ok {
		stream["finalmask"] = m
	}
	tls := obj(o, "tls")
	if tls["enabled"] == true {
		security := "tls"
		reality := obj(tls, "reality")
		if reality["enabled"] == true {
			security = "reality"
		}
		stream["security"] = security
		fields := M{"serverName": tls["server_name"]}
		utls := obj(tls, "utls")
		if utls["enabled"] == true {
			fields["fingerprint"] = utls["fingerprint"]
		}
		if security == "reality" {
			fields["password"] = reality["public_key"]
			fields["shortId"] = str(reality, "short_id")
			if fields["fingerprint"] == nil {
				fields["fingerprint"] = "chrome"
			}
		} else if tls["alpn"] != nil {
			fields["alpn"] = tls["alpn"]
		}
		stream[security+"Settings"] = fields
	}
	tr := obj(o, "transport")
	switch str(tr, "type") {
	case "":
	case "ws":
		stream["network"] = "ws"
		headers := obj(tr, "headers")
		stream["wsSettings"] = M{"path": tr["path"], "headers": headers}
	case "grpc":
		stream["network"] = "grpc"
		stream["grpcSettings"] = M{"serviceName": str(tr, "service_name")}
	case "httpupgrade":
		stream["network"] = "httpupgrade"
		stream["httpupgradeSettings"] = M{"path": tr["path"], "host": str(tr, "host")}
	default:
		return nil, errors.New("stored transport unsupported")
	}
	return M{"protocol": o["type"], "tag": "node-" + n.ID, "settings": settings, "streamSettings": stream}, nil
}
func Generate(s State, mode string, port int) (M, error) {
	if mode != "proxy" && mode != "tun" || port < 1 || port > 65534 {
		return nil, errors.New("invalid mode or port")
	}
	if s.Default != "direct" && s.Default != "proxy" {
		return nil, errors.New("invalid default route")
	}
	nodes := s.Nodes()
	if len(nodes) == 0 {
		return nil, errors.New("add a subscription first")
	}
	tags := []string{}
	found := s.Selected == "auto"
	outs := []M{}
	for _, n := range nodes {
		tags = append(tags, "node-"+n.ID)
		found = found || n.ID == s.Selected
		o, e := Outbound(n)
		if e != nil {
			return nil, e
		}
		outs = append(outs, o)
	}
	if !found {
		return nil, errors.New("selected server disappeared; choose a server or auto")
	}
	target := func(r M, action string) M {
		if action == "proxy" {
			if s.Selected == "auto" {
				r["balancerTag"] = "auto"
			} else {
				r["outboundTag"] = "node-" + s.Selected
			}
		} else {
			r["outboundTag"] = action
		}
		return r
	}
	resolver := func(action string, domains []string) M {
		address := s.DNS[action]
		if address == "" {
			address = "https://1.1.1.1/dns-query"
		}
		r := M{"address": address, "tag": "dns-" + action}
		if len(domains) > 0 {
			r["domains"] = domains
			r["skipFallback"] = true
			r["finalQuery"] = true
		}
		return r
	}
	rules := []M{{"type": "field", "inboundTag": []string{"dns-direct"}, "outboundTag": "direct"}, target(M{"type": "field", "inboundTag": []string{"dns-proxy"}}, "proxy"), {"type": "field", "port": "53", "outboundTag": "dns-out"}}
	dns := []M{}
	effective, e := effectiveRules(s)
	if e != nil {
		return nil, e
	}
	for _, r := range effective {
		v := r.Value
		switch r.Kind {
		case "domain":
			v = "full:" + v
		case "suffix":
			v = "domain:" + v
		case "geoip", "geosite":
			digest := s.Geodata[r.Kind].SHA
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
				return nil, errors.New("geodata missing; run whale geodata update")
			}
			v = fmt.Sprintf("ext:%s.dat:%s", digest, v)
		}
		rule := target(M{"type": "field", ruleFields[r.Kind]: []string{v}}, r.Action)
		if r.Kind == "process" || r.Kind == "path" {
			rule["inboundTag"] = []string{"tun-in"}
		}
		rules = append(rules, rule)
		if r.Kind == "domain" || r.Kind == "suffix" || r.Kind == "geosite" {
			a := r.Action
			if a == "block" {
				a = s.Default
			}
			dns = append(dns, resolver(a, []string{v}))
		}
	}
	rules = append(rules, M{"type": "field", "ip": privateIPs, "outboundTag": "direct"}, target(M{"type": "field", "network": "tcp,udp"}, s.Default))
	sniff := M{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false}
	ins := []M{{"tag": "socks-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": M{"auth": "noauth", "udp": true}, "sniffing": sniff}, {"tag": "http-in", "listen": "127.0.0.1", "port": port + 1, "protocol": "http", "settings": M{}, "sniffing": sniff}}
	if mode == "tun" {
		ins = append(ins, M{"tag": "tun-in", "protocol": "tun", "settings": M{"mtu": 1500, "gateway": []string{"172.28.0.1/30"}, "autoSystemRoutingTable": []string{"0.0.0.0/0", "::/0"}, "autoOutboundsInterface": "auto"}, "sniffing": sniff})
	}
	dns = append(dns, resolver(s.Default, nil))
	strategy := s.DNS["strategy"]
	if strategy == "" {
		strategy = "UseIP"
	}
	outs = append(outs, M{"protocol": "freedom", "tag": "direct", "settings": M{"domainStrategy": "UseIP"}}, M{"protocol": "blackhole", "tag": "block", "settings": M{}}, M{"protocol": "dns", "tag": "dns-out", "settings": M{}})
	routing := M{"domainStrategy": "IPOnDemand", "rules": rules}
	config := M{"log": M{"loglevel": "warning"}, "inbounds": ins, "dns": M{"servers": dns, "tag": "dns-" + s.Default, "queryStrategy": strategy, "disableFallbackIfMatch": true}, "outbounds": outs, "routing": routing}
	if s.Selected == "auto" {
		routing["balancers"] = []M{{"tag": "auto", "selector": tags, "fallbackTag": tags[0], "strategy": M{"type": "leastPing"}}}
		config["observatory"] = M{"subjectSelector": tags, "probeURL": s.TestURL, "probeInterval": "5m", "enableConcurrency": true}
	}
	return config, nil
}
