package whale

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

func clean(s string) string {
	r := []rune(strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s))
	if len(r) > 120 {
		r = r[:120]
	}
	return string(r)
}
func pythonJSON(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		a := []string{}
		for _, k := range keys {
			a = append(a, pythonJSON(k)+": "+pythonJSON(x[k]))
		}
		return "{" + strings.Join(a, ", ") + "}"
	case string:
		b, _ := json.Marshal(x)
		s := string(b)
		s = strings.ReplaceAll(s, `\u003c`, "<")
		s = strings.ReplaceAll(s, `\u003e`, ">")
		s = strings.ReplaceAll(s, `\u0026`, "&")
		var out strings.Builder
		for _, r := range s {
			if r > 127 {
				if r > 0xffff {
					a, b := utf16.EncodeRune(r)
					fmt.Fprintf(&out, `\u%04x\u%04x`, a, b)
				} else {
					fmt.Fprintf(&out, `\u%04x`, r)
				}
			} else {
				out.WriteRune(r)
			}
		}
		return out.String()
	case []any:
		a := []string{}
		for _, z := range x {
			a = append(a, pythonJSON(z))
		}
		return "[" + strings.Join(a, ", ") + "]"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}
func ParseURI(raw string) (Node, error) {
	bad := func(msg string) (Node, error) { return Node{}, errors.New(msg) }
	u, e := url.Parse(raw)
	if e != nil {
		return bad("invalid server URI")
	}
	if u.Scheme != "vless" && u.Scheme != "trojan" {
		return bad("supported protocols: vless, trojan")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 || u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return bad("missing server, port or credentials")
	}
	if _, ok := u.User.Password(); ok {
		return bad("invalid credentials")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return bad("invalid query")
	}
	allowed := strings.Fields("type security encryption flow fp pbk sid sni spx alpn allowInsecure insecure path host serviceName headerType fm")
	for k, v := range q {
		found := false
		for _, a := range allowed {
			if a == k {
				found = true
			}
		}
		if !found {
			return bad("unsupported connection parameter: " + clean(k))
		}
		if len(v) != 1 {
			return bad("duplicate connection parameter")
		}
	}
	get := func(k, d string) string {
		if v, ok := q[k]; ok {
			return v[0]
		}
		return d
	}
	tr := get("type", "tcp")
	if !strings.Contains("|tcp|raw|ws|grpc|httpupgrade|", "|"+tr+"|") {
		return bad("unsupported transport")
	}
	if get("encryption", "none") != "none" || get("headerType", "none") != "none" {
		return bad("unsupported encryption or TCP header")
	}
	o := M{"type": u.Scheme, "server": u.Hostname(), "server_port": port}
	if u.Scheme == "vless" {
		id := strings.ToLower(strings.ReplaceAll(u.User.Username(), "-", ""))
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
			return bad("invalid VLESS UUID")
		}
		o["uuid"] = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
		flow := get("flow", "")
		if flow != "" {
			if flow != "xtls-rprx-vision" || tr != "tcp" && tr != "raw" {
				return bad("unsupported VLESS flow")
			}
			o["flow"] = flow
		}
	} else {
		o["password"] = u.User.Username()
	}
	security := get("security", "none")
	if u.Scheme == "trojan" {
		security = get("security", "tls")
	}
	if security != "none" && security != "tls" && security != "reality" {
		return bad("unsupported security")
	}
	if security != "none" {
		tls := M{"enabled": true, "server_name": get("sni", u.Hostname())}
		insecure := get("allowInsecure", get("insecure", "0"))
		if insecure != "0" && insecure != "false" && insecure != "" {
			return bad("insecure TLS is not accepted")
		}
		if a := get("alpn", ""); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		if get("fp", "") != "" || security == "reality" {
			tls["utls"] = M{"enabled": true, "fingerprint": get("fp", "chrome")}
		}
		if security == "reality" {
			if get("pbk", "") == "" {
				return bad("Reality key required")
			}
			tls["reality"] = M{"enabled": true, "public_key": get("pbk", ""), "short_id": get("sid", "")}
		}
		o["tls"] = tls
	} else if get("flow", "") != "" {
		return bad("Vision requires TLS/Reality")
	}
	if _, ok := q["fm"]; ok {
		var fm M
		if json.Unmarshal([]byte(get("fm", "")), &fm) != nil {
			return bad("invalid fm JSON")
		}
		if e = validateMask(fm); e != nil {
			return Node{}, e
		}
		o["finalmask"] = fm
	}
	if tr != "tcp" && tr != "raw" {
		t := M{"type": tr}
		if tr == "grpc" {
			t["service_name"] = get("serviceName", "")
		} else {
			t["path"] = get("path", "/")
			if h := get("host", ""); h != "" {
				if tr == "ws" {
					t["headers"] = M{"Host": h}
				} else {
					t["host"] = h
				}
			}
		}
		o["transport"] = t
	}
	// Normalize arrays and numbers before reproducing the legacy stable identity.
	b, _ := json.Marshal(o)
	_ = json.Unmarshal(b, &o)
	sum := sha256.Sum256([]byte(pythonJSON(o)))
	name := u.Fragment
	if name == "" {
		name = strings.ToUpper(u.Scheme)
	}
	return Node{hex.EncodeToString(sum[:])[:16], name, o}, nil
}
func validateMask(m M) error {
	bad := errors.New("unsupported or invalid fm fragmentation settings")
	a, ok := m["tcp"].([]any)
	if !ok || len(m) != 1 || len(a) != 1 {
		return bad
	}
	v, ok := a[0].(map[string]any)
	if !ok || len(v) != 2 || str(v, "type") != "fragment" {
		return bad
	}
	s := obj(v, "settings")
	if len(s) != 3 || str(s, "packets") != "tlshello" {
		return bad
	}
	for _, k := range []string{"length", "delay"} {
		v := str(s, k)
		if !regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`).MatchString(v) {
			return bad
		}
		p := strings.Split(v, "-")
		lo, _ := strconv.Atoi(p[0])
		hi, _ := strconv.Atoi(p[len(p)-1])
		min, max := 0, 60000
		if k == "length" {
			min, max = 1, 65535
		}
		if lo < min || lo > hi || hi > max {
			return bad
		}
	}
	return nil
}
func decode64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, e := enc.DecodeString(s)
		if e == nil {
			return b, nil
		}
	}
	return nil, errors.New("expected plain or Base64 URI subscription")
}
func ParseSubscription(b []byte) ([]Node, error) {
	if len(b) > 2000000 {
		return nil, errors.New("subscription exceeds 2 MB")
	}
	s := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if !strings.HasPrefix(s, "vless://") && !strings.HasPrefix(s, "trojan://") {
		var e error
		b, e = decode64(s)
		if e != nil {
			return nil, e
		}
		s = string(b)
	}
	out := []Node{}
	seen := map[string]bool{}
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, e := ParseURI(line)
		if e != nil {
			return nil, fmt.Errorf("subscription entry #%d: %w; cache preserved", i+1, e)
		}
		if !seen[n.ID] {
			out = append(out, n)
			seen[n.ID] = true
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty subscription")
	}
	return out, nil
}
func download(address string, limit int64) ([]byte, http.Header, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" {
		return nil, nil, errors.New("URL must use HTTPS")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 10 {
			return errors.New("redirect refused")
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(operationContext, "GET", address, nil)
	if e != nil {
		return nil, nil, errors.New("invalid URL")
	}
	req.Header.Set("User-Agent", "whale/"+Version)
	r, e := client.Do(req)
	if e != nil {
		return nil, nil, errors.New("download failed; cache preserved")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, nil, fmt.Errorf("download HTTP %d; cache preserved", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || len(b) == 0 || int64(len(b)) > limit {
		return nil, nil, errors.New("empty, oversized or incomplete download")
	}
	return b, r.Header, nil
}
func Fetch(address string, interval int) (Subscription, error) {
	if interval < 60 {
		return Subscription{}, errors.New("minimum interval is 60 seconds")
	}
	b, h, e := download(address, 2000000)
	if e != nil {
		return Subscription{}, e
	}
	nodes, e := ParseSubscription(b)
	if e != nil {
		return Subscription{}, e
	}
	title := h.Get("Profile-Title")
	if strings.HasPrefix(strings.ToLower(title), "base64:") {
		decoded, _ := decode64(title[7:])
		title = string(decoded)
	}
	title = clean(strings.TrimSpace(title))
	if title == "" {
		u, _ := url.Parse(address)
		title = u.Hostname()
	}
	return Subscription{address, interval, float64(time.Now().Unix()), nodes, title}, nil
}
