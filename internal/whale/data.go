package whale

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const geoURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/%s.dat"

func LoadPreset(source string, interval int) (Preset, error) {
	p := Preset{Source: source, Interval: interval, Updated: float64(time.Now().Unix()), Enabled: true}
	if interval < 60 {
		return p, errors.New("minimum interval is 60 seconds")
	}
	if strings.HasPrefix(source, "builtin:") {
		switch source {
		case "builtin:lan":
			for _, v := range privateIPs {
				p.Rules = append(p.Rules, Rule{"cidr", v, "direct"})
			}
		case "builtin:ads":
			p.Rules = []Rule{{"geosite", "category-ads-all", "block"}}
		default:
			return p, errors.New("unknown built-in preset")
		}
		return p, nil
	}
	var b []byte
	var e error
	if strings.Contains(source, "://") {
		b, _, e = download(source, 2000000)
	} else {
		p.Source = canonical(source)
		f, err := os.Open(p.Source)
		if err != nil {
			return p, err
		}
		defer f.Close()
		b, e = readLimit(f, 2000000)
	}
	if e != nil {
		return p, e
	}
	var doc struct {
		Version     int    `json:"version"`
		Rules       []Rule `json:"rules"`
		Description string `json:"description"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || doc.Version != 1 || len(doc.Rules) < 1 || len(doc.Rules) > 5000 {
		return p, errors.New("preset requires version 1 and 1..5000 rules")
	}
	for _, r := range doc.Rules {
		v, e := MakeRule(r.Kind, r.Value, r.Action)
		if e != nil {
			return p, e
		}
		p.Rules = append(p.Rules, v)
	}
	return p, nil
}
func FetchAsset(s Store, kind, address string, interval int) (Asset, error) {
	if interval < 60 {
		return Asset{}, errors.New("minimum interval is 60 seconds")
	}
	b, _, e := download(address, 64000000)
	if e != nil {
		return Asset{}, e
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(s.Profile, "geodata")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return Asset{}, e
	}
	if e = inheritOwner(dir, s.Profile); e != nil {
		return Asset{}, e
	}
	if e = atomicWrite(filepath.Join(dir, digest+".dat"), b, 0600); e != nil {
		return Asset{}, e
	}
	return Asset{address, digest, float64(time.Now().Unix()), interval}, nil
}
func protoFields(b []byte) (map[uint64][][]byte, error) {
	out := map[uint64][][]byte{}
	bad := errors.New("invalid geodata protobuf")
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, bad
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, bad
			}
			b = b[n:]
		case 1, 5:
			size := 8
			if tag&7 == 5 {
				size = 4
			}
			if len(b) < size {
				return nil, bad
			}
			b = b[size:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, bad
			}
			b = b[n:]
			out[tag>>3] = append(out[tag>>3], b[:int(l)])
			b = b[int(l):]
		default:
			return nil, bad
		}
	}
	return out, nil
}
func firstCategory(b []byte) (string, error) {
	fields, e := protoFields(b)
	if e != nil {
		return "", e
	}
	for _, entry := range fields[1] {
		f, e := protoFields(entry)
		if e != nil {
			return "", e
		}
		for _, v := range f[1] {
			r, e := MakeRule("geosite", string(v), "direct")
			return r.Value, e
		}
	}
	return "", errors.New("geodata contains no categories")
}
func ValidateAssets(s Store, core string, state State) error {
	for kind, a := range state.Geodata {
		if kind != "geoip" && kind != "geosite" {
			return errors.New("unknown geodata kind")
		}
		if len(a.SHA) != 64 || strings.Trim(a.SHA, "0123456789abcdef") != "" {
			return errors.New("invalid geodata digest")
		}
		b, e := os.ReadFile(filepath.Join(s.Profile, "geodata", a.SHA+".dat"))
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != a.SHA {
			return errors.New("geodata checksum mismatch")
		}
		category, e := firstCategory(b)
		if e != nil {
			return e
		}
		field := "domain"
		if kind == "geoip" {
			field = "ip"
		}
		c := M{"outbounds": []M{{"protocol": "freedom", "tag": "direct"}}, "routing": M{"rules": []M{{"type": "field", "outboundTag": "direct", field: []string{fmt.Sprintf("ext:%s.dat:%s", a.SHA, category)}}}}}
		if e = ValidateConfig(s, core, c); e != nil {
			return e
		}
	}
	return nil
}
func Refresh(s Store, v *State) error {
	now := float64(time.Now().Unix())
	for _, k := range v.Subscriptions.Keys {
		p := v.Subscriptions.Values[k]
		if now-p.Updated >= float64(p.Interval) {
			n, e := Fetch(p.URL, p.Interval)
			if e != nil {
				return e
			}
			v.Subscriptions.Set(k, n)
		}
	}
	for _, k := range v.Presets.Keys {
		p := v.Presets.Values[k]
		if p.Enabled && strings.HasPrefix(p.Source, "https://") && now-p.Updated >= float64(p.Interval) {
			n, e := LoadPreset(p.Source, p.Interval)
			if e != nil {
				return e
			}
			v.Presets.Set(k, n)
		}
	}
	for k, a := range v.Geodata {
		if now-a.Updated >= float64(a.Interval) {
			n, e := FetchAsset(s, k, a.URL, a.Interval)
			if e != nil {
				return e
			}
			v.Geodata[k] = n
		}
	}
	return nil
}
