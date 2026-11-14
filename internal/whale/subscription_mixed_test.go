package whale

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMixedSubscription(t *testing.T) {
	body := "ss://unsupported@example.org:443#SS\ntrojan://secret@example.org:443?security=tls#Working\nvmess://unsupported"
	for _, data := range []string{body, base64.StdEncoding.EncodeToString([]byte(body))} {
		nodes, skipped, e := parseSubscriptionDetails([]byte(data))
		if e != nil || len(nodes) != 1 || skipped != 2 {
			t.Fatal(len(nodes), skipped, e)
		}
	}
}
func TestUnsupportedSubscriptionPreservesCache(t *testing.T) {
	for _, data := range []string{"ss://unsupported", "ss://unsupported\nvless://invalid"} {
		nodes, _, e := parseSubscriptionDetails([]byte(data))
		if e == nil || nodes != nil || !strings.Contains(e.Error(), "cache preserved") {
			t.Fatal(nodes, e)
		}
	}
}
