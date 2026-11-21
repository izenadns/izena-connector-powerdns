package internal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestProbeReturnsSupportedAuthoritativeProfile(t *testing.T) {
	var method string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method
		if request.URL.Path != "/api/v1/servers/localhost" {
			t.Fatalf("request path = %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"type":"Server","daemon_type":"Authoritative","version":"5.0.2","new_field":{"future":true}}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, ServerID: "localhost"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	profile, err := client.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if method != http.MethodGet {
		t.Fatalf("probe method = %q, want GET", method)
	}
	if profile.DaemonType != "Authoritative" || profile.Version != "5.0.2" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestProbeAcceptsLowercaseDaemonTypeAndVPrefixedVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"type":"Server","daemon_type":"authoritative","version":"v5.1.0"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	profile, err := client.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if profile.Version != "v5.1.0" {
		t.Fatalf("profile version = %s, want v5.1.0", profile.Version)
	}
}

func TestProbeClassifiesUnsupportedServerAndVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "recursor", body: `{"type":"Server","daemon_type":"Recursor","version":"5.0.0"}`},
		{name: "version", body: `{"type":"Server","daemon_type":"Authoritative","version":"6.0.0"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			_, err = client.Probe(context.Background())
			if !errors.Is(err, connector.ErrUnsupported) {
				t.Fatalf("Probe() error = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestProbeClassifiesMalformedMetadata(t *testing.T) {
	tests := []string{
		"not-json",
		`{"type":"Authoritative","version":"5.0.0"}`,
		`{"type":"Server","daemon_type":"Authoritative"}`,
		`{"type":"Server","daemon_type":"Authoritative","version":"unknown"}`,
		`{"type":"Server","daemon_type":"Authoritative","version":"5."}`,
		`{"type":"Server","daemon_type":"Authoritative","version":"5.` + strings.Repeat("0", maxProfileVersionLength) + `"}`,
		`{"type":"Server","daemon_type":"Authoritative","version":"v` + strings.Repeat("0", maxProfileVersionLength) + `"}`,
		`{"type":"Server","daemon_type":"Authoritative","version":"5.0.0` + "\n" + `"}`,
	}
	for _, body := range tests {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			_, err = client.Probe(context.Background())
			if !errors.Is(err, connector.ErrMalformed) {
				t.Fatalf("Probe() error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestProbeDoesNotPerformMutation(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		_, _ = writer.Write([]byte(`{"type":"Server","daemon_type":"Authoritative","version":"5.0.0"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("probe methods = %v, want one GET", methods)
	}
}
