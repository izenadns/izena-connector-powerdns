package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestGetDNSSECMapsZoneAndSanitizedCryptokeyStatus(t *testing.T) {
	requests := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		switch request.URL.Path {
		case "/api/v1/servers/localhost/zones/example.org.":
			if request.URL.Query().Get("rrsets") != "false" {
				t.Fatalf("query = %s, want rrsets=false", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","dnssec":true,"privatekey":"must-not-escape"}`))
		case "/api/v1/servers/localhost/zones/example.org./cryptokeys":
			_, _ = writer.Write([]byte(`[{"id":1,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID","algorithm":"ECDSAP256SHA256","bits":256,"ds":["2064 13 2 AABB"],"privatekey":"canary-private-key"}]`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	status, err := client.GetDNSSEC(context.Background(), "example.org.")
	if err != nil {
		t.Fatalf("GetDNSSEC() error = %v", err)
	}
	if !status.Enabled || status.Active == nil || !*status.Active {
		t.Fatalf("status = %+v, want enabled active", status)
	}
	if len(status.Keys) != 1 {
		t.Fatalf("keys = %+v, want one public key", status.Keys)
	}
	key := status.Keys[0]
	if key.ID != 1 || key.KeyType != "ksk" || !key.Active || !key.Published {
		t.Fatalf("key = %+v, want mapped public metadata", key)
	}
	if key.KeyTag != 2064 {
		t.Fatalf("key tag = %v, want RFC 4034 tag 2064", key.KeyTag)
	}
	if key.Algorithm == nil || *key.Algorithm != "ECDSAP256SHA256" || key.Bits == nil || *key.Bits != 256 {
		t.Fatalf("algorithm/bits = %v/%v, want ECDSAP256SHA256/256", key.Algorithm, key.Bits)
	}
	if len(key.DS) != 1 || key.DS[0] != "2064 13 2 AABB" {
		t.Fatalf("ds = %v, want public DS record", key.DS)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %v, want zone and cryptokeys", requests)
	}
}

func TestGetDNSSECMapsDisabledWithoutKeyRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","dnssec":false}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	status, err := client.GetDNSSEC(context.Background(), "example.org.")
	if err != nil || status.Enabled || status.Active != nil {
		t.Fatalf("status = %+v, error = %v", status, err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one zone request", requests)
	}
}

func TestGetDNSSECRejectsIncompleteCryptokeyCatalog(t *testing.T) {
	for _, test := range []struct {
		name string
		key  string
	}{
		{name: "missing identity", key: `{"active":true,"published":true,"dnskey":"257 3 13 AQID","ds":[]}`},
		{name: "unknown key type", key: `{"id":2,"keytype":"unknown","active":true,"published":true,"dnskey":"257 3 13 AQID","ds":[]}`},
		{name: "missing activity", key: `{"id":2,"keytype":"ksk","published":true,"dnskey":"257 3 13 AQID","ds":[]}`},
		{name: "missing publication", key: `{"id":2,"keytype":"ksk","active":true,"dnskey":"257 3 13 AQID","ds":[]}`},
		{name: "missing DNSKEY", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"ds":[]}`},
		{name: "malformed DNSKEY", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"not a DNSKEY","ds":["2064 13 2 AABB"]}`},
		{name: "missing delegation material", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID"}`},
		{name: "empty delegation value", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID","ds":[""]}`},
		{name: "oversized DNSKEY", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"` + strings.Repeat("A", 65536) + `","ds":[]}`},
		{name: "oversized delegation value", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID","ds":["` + strings.Repeat("A", 2049) + `"]}`},
		{name: "oversized delegation catalog", key: `{"id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID","ds":[` + strings.TrimSuffix(strings.Repeat(`"2064 13 2 AABB",`, 9), ",") + `]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/cryptokeys") {
					_, _ = writer.Write([]byte(`[{"id":1,"keytype":"ksk","active":true,"published":true,"dnskey":"257 3 13 AQID","ds":[]},` + test.key + `]`))
					return
				}
				_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","dnssec":true}`))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			status, err := client.GetDNSSEC(t.Context(), "example.org.")
			if !errors.Is(err, connector.ErrMalformed) || status.Enabled || status.Keys != nil {
				t.Fatalf("DNSSEC = %+v, error = %v; want malformed catalog without a partial result", status, err)
			}
		})
	}
}

func TestGetDNSSECKeepsCompleteEmptyAndUnpublishedCatalogs(t *testing.T) {
	for _, test := range []struct {
		name      string
		keys      string
		count     int
		active    bool
		published bool
	}{
		{name: "empty", keys: `[]`},
		{name: "unpublished ZSK", keys: `[{"id":1,"keytype":"zsk","active":true,"published":false,"dnskey":"256 3 13 AQID"}]`, count: 1, active: true},
		{name: "inactive published CSK", keys: `[{"id":1,"keytype":"csk","active":false,"published":true,"dnskey":"257 3 13 AQID","ds":[]}]`, count: 1, published: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/cryptokeys") {
					_, _ = writer.Write([]byte(test.keys))
					return
				}
				_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","dnssec":true}`))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			status, err := client.GetDNSSEC(t.Context(), "example.org.")
			if err != nil || !status.Enabled || status.Keys == nil || len(status.Keys) != test.count || status.Active == nil || *status.Active != test.active {
				t.Fatalf("DNSSEC = %+v, error = %v; want complete catalog", status, err)
			}
			if test.count > 0 && status.Keys[0].Published != test.published {
				t.Fatal("key activity changed its independent publication state")
			}
		})
	}
}

func TestGetDNSSECPropagatesMissingCryptokeyCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/servers/localhost/zones/example.org.":
			_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","dnssec":true}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	status, err := client.GetDNSSEC(context.Background(), "example.org.")
	if !errors.Is(err, connector.ErrNotFound) || status.Enabled || status.Keys != nil {
		t.Fatalf("status = %+v, error = %v; want missing catalog without a success result", status, err)
	}
}

func TestGetDNSSECDistinguishesUnsupportedFromDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.GetDNSSEC(context.Background(), "example.org.")
	if !errors.Is(err, connector.ErrUnsupported) {
		t.Fatalf("error = %v, want unsupported", err)
	}
}

func TestGetDNSSECRejectsMissingZoneMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"dnssec":false}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.GetDNSSEC(context.Background(), "example.org.")
	if !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("error = %v, want malformed", err)
	}
}

func TestSetDNSSECUsesZoneUpdateWithoutKeyMaterial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/api/v1/servers/localhost/zones/example.org." {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["dnssec"] != true || len(body) != 1 {
			t.Fatalf("request body = %#v, want only dnssec=true", body)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.SetDNSSEC(context.Background(), "example.org.", true); err != nil {
		t.Fatalf("SetDNSSEC() error = %v", err)
	}
}
