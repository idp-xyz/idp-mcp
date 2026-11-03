package transport

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadBounded(t *testing.T) {
	if b, err := ReadBounded(strings.NewReader("abcd"), 4); err != nil || string(b) != "abcd" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadBounded(strings.NewReader("abcde"), 4); err != ErrTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestParseMessageJSONAndSSE(t *testing.T) {
	m, err := ParseMessage("application/json; charset=utf-8", []byte(` {"jsonrpc":"2.0","id":1,"result":{}} `))
	if err != nil || !bytes.HasPrefix(m, []byte(`{"jsonrpc"`)) {
		t.Fatalf("%s %v", m, err)
	}
	sse := "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1,\"result\":{}}\r\n\r\n: keepalive\n\nevent: ping\ndata: x\n\n"
	m, err = ParseMessage("text/event-stream", []byte(sse))
	if err != nil || string(m) != "{\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{}}" {
		t.Fatalf("%q %v", m, err)
	}
}

func TestParseMessageRefusals(t *testing.T) {
	for _, c := range []struct{ ct, body string }{
		{"application/json", "{nope"},
		{"text/html", "<html>"},
		{"text/event-stream", "data: {}\n\ndata: {}\n\n"},
		{"text/event-stream", ": only comments\n\n"},
		{"text/event-stream", "data: {bad\n\n"},
	} {
		if _, err := ParseMessage(c.ct, []byte(c.body)); err == nil {
			t.Errorf("%s %q accepted", c.ct, c.body)
		}
	}
}
