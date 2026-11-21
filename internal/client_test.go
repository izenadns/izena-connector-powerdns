package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/izenadns/izena-connector-contract/connector"
)

type recordingObserver struct {
	mu        sync.Mutex
	operation string
	status    string
	durations int
}

func (o *recordingObserver) ObserveDNSProvider(_, operation, statusClass string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.operation, o.status, o.durations = operation, statusClass, o.durations+1
}

func TestClientObservesBoundedOperationOutcome(t *testing.T) {
	observer := &recordingObserver{}
	client, err := NewClient(Config{BaseURL: "https://dns.example.test", Metrics: observer})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.http.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	if _, err := client.Do(context.Background(), http.MethodGet, []string{"zones", "zone-with-user-data"}, nil); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.operation != "GET zones" || observer.status != "2xx" || observer.durations != 1 {
		t.Fatalf("observation = (%q, %q, %d), want GET zones/2xx/1", observer.operation, observer.status, observer.durations)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
		ok   bool
	}{
		{name: "https", url: "HTTPS://dns.example.test/edge/", want: "https://dns.example.test/edge", ok: true},
		{name: "http", url: "http://127.0.0.1:8081", want: "http://127.0.0.1:8081", ok: true},
		{name: "userinfo", url: "https://user:credential@dns.example.test", ok: false}, // #nosec G101 -- intentionally tests rejecting URL userinfo
		{name: "query", url: "https://dns.example.test/?redirect=https://other.example.test", ok: false},
		{name: "fragment", url: "https://dns.example.test/#fragment", ok: false},
		{name: "encoded separator", url: "https://dns.example.test/edge%2Fv1", ok: false},
		{name: "repeated path separator", url: "https://dns.example.test/edge//v1", ok: false},
		{name: "unsupported", url: "ftp://dns.example.test", ok: false},
		{name: "relative", url: "/dns", ok: false},
		{name: "dot segment", url: "https://dns.example.test/edge/../api", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(test.url)
			if test.ok {
				if err != nil || got != test.want {
					t.Fatalf("NormalizeBaseURL() = %q, %v; want %q", got, err, test.want)
				}
				return
			}
			if !errors.Is(err, connector.ErrInvalidServerURL) {
				t.Fatalf("NormalizeBaseURL() error = %v, want ErrInvalidServerURL", err)
			}
		})
	}
}

func TestClientEscapesServerIDAndPreservesOriginPath(t *testing.T) {
	for _, prefix := range []string{"/proxy/", "/proxy%20edge/"} {
		t.Run(prefix, func(t *testing.T) {
			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				gotPath = request.URL.EscapedPath()
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`{"type":"Server","daemon_type":"Authoritative","version":"5.0.0"}`))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL + prefix, ServerID: "edge/core", APIKey: "secret"})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			response, err := client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			wantPath := strings.TrimRight(prefix, "/") + "/api/v1/servers/edge%2Fcore/server"
			if gotPath != wantPath {
				t.Fatalf("request path = %q, want %q", gotPath, wantPath)
			}
			if !strings.Contains(string(response.Body), "Authoritative") {
				t.Fatalf("response body = %q", response.Body)
			}
		})
	}
}

func TestClientRejectsAmbiguousServerIDSegments(t *testing.T) {
	for _, serverID := range []string{"edge//core", "edge/./core", "edge/../core", "edge\\core"} {
		t.Run(serverID, func(t *testing.T) {
			if _, err := NewClient(Config{BaseURL: "https://dns.example.test", ServerID: serverID}); !errors.Is(err, connector.ErrInvalidServer) {
				t.Fatalf("NewClient(%q) error = %v, want ErrInvalidServer", serverID, err)
			}
		})
	}
}

func TestClientDoesNotFollowRedirectsWithCredentials(t *testing.T) {
	var received bool
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", destination.URL+"/stolen")
		writer.WriteHeader(http.StatusFound)
	}))
	defer source.Close()
	client, err := NewClient(Config{BaseURL: source.URL, APIKey: "do-not-forward"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
	if !errors.Is(err, connector.ErrRedirect) {
		t.Fatalf("Do() error = %v, want ErrRedirect", err)
	}
	if received {
		t.Fatal("redirect destination received a request")
	}
}

func TestClientUsesConfiguredCABundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewClient(Config{BaseURL: server.URL, CABundlePEM: string(cert)})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	response, err := client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
}

func TestClientRejectsInvalidCABundle(t *testing.T) {
	_, err := NewClient(Config{BaseURL: "https://dns.example.test", CABundlePEM: "not a certificate"})
	if !errors.Is(err, connector.ErrInvalidServerTLS) {
		t.Fatalf("NewClient() error = %v, want ErrInvalidServerTLS", err)
	}
}

func TestClientRequestTimeoutIsTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
	if !errors.Is(err, connector.ErrTimeout) {
		t.Fatalf("Do() error = %v, want ErrTimeout", err)
	}
}

func TestClientBodyTimeoutIsTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(100 * time.Millisecond)
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
	if !errors.Is(err, connector.ErrTimeout) {
		t.Fatalf("Do() error = %v, want ErrTimeout", err)
	}
}

func TestTLSFailureRecognizesCertificateVerificationErrors(t *testing.T) {
	err := &tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired}}
	if !isTLSFailure(err) {
		t.Fatalf("isTLSFailure() = false for certificate verification error")
	}
}

func TestClientMapsUpstreamStatusWithoutLeakingResponseBody(t *testing.T) {
	tests := []struct {
		name string
		code int
		want error
	}{
		{name: "unauthorized", code: http.StatusUnauthorized, want: connector.ErrAuthentication},
		{name: "forbidden", code: http.StatusForbidden, want: connector.ErrAuthentication},
		{name: "not found", code: http.StatusNotFound, want: connector.ErrNotFound},
		{name: "conflict", code: http.StatusConflict, want: connector.ErrConflict},
		{name: "validation", code: http.StatusUnprocessableEntity, want: connector.ErrValidation},
		{name: "timeout", code: http.StatusRequestTimeout, want: connector.ErrTimeout},
		{name: "server failure", code: http.StatusBadGateway, want: connector.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const responseMarker = "upstream-body-must-not-escape"
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.code)
				_, _ = writer.Write([]byte(responseMarker))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "private-api-key"})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			_, err = client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("Do() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), responseMarker) || strings.Contains(err.Error(), "private-api-key") {
				t.Fatalf("error leaked sensitive response data: %v", err)
			}
		})
	}
}

func TestClientRetainsPowerDNSDiagnostic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = writer.Write([]byte(`{"error":"rrset content for secret.example. is invalid","errors":["unknown token value"]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), http.MethodPatch, []string{"zones", "example.org."}, []byte(`{}`))
	if !errors.Is(err, connector.ErrValidation) || connector.ErrorDetail(err) != "rrset content for secret.example. is invalid; unknown token value" || connector.ErrorStatusCode(err) != http.StatusUnprocessableEntity {
		t.Fatalf("error = %v, detail = %q, status = %d", err, connector.ErrorDetail(err), connector.ErrorStatusCode(err))
	}
}

func TestLongPowerDNSDiagnosticsRetainABoundedValidPrefix(t *testing.T) {
	for _, reason := range []string{
		strings.Repeat("x", maxResponseDiagnosticLength+1),
		strings.Repeat("x", maxResponseDiagnosticLength-4) + "é" + strings.Repeat("y", 20),
	} {
		body := []byte(`{"error":"` + reason + `"}`)
		detail := connector.ErrorDetail(statusError(http.StatusUnprocessableEntity, body))
		if detail == "" || len(detail) > maxResponseDiagnosticLength || !utf8.ValidString(detail) || !strings.HasSuffix(detail, "...") {
			t.Fatalf("long diagnostic lost its bounded, valid prefix: %q", detail)
		}
		if !strings.HasPrefix(reason, strings.TrimSuffix(detail, "...")) {
			t.Fatalf("diagnostic prefix changed the rejection reason: %q", detail)
		}
	}
	for _, body := range []string{
		`{"error":`,
		`{"error":"` + strings.Repeat("x", maxResponseDiagnosticLength+1) + `\u0000"}`,
	} {
		if detail := connector.ErrorDetail(statusError(http.StatusUnprocessableEntity, []byte(body))); detail != "" {
			t.Fatalf("malformed or NUL-bearing diagnostic was retained: %q", detail)
		}
	}
}

func TestClientBoundsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, []string{"server"}, nil)
	if !errors.Is(err, connector.ErrResponseTooLarge) {
		t.Fatalf("Do() error = %v, want ErrResponseTooLarge", err)
	}
}

func TestClientSendsKeyOnlyToConfiguredOrigin(t *testing.T) {
	const apiKey = "configured-origin-only"
	var receivedKey string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedKey = request.Header.Get("X-API-Key")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: apiKey})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, []string{"server"}, nil); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if receivedKey != apiKey {
		t.Fatalf("X-API-Key = %q, want configured key", receivedKey)
	}
}

func TestClientDoesNotRetryMutation(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		attempts++
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte("do not retry"))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodPost, []string{"server"}, []byte(`{"mutation":true}`))
	if !errors.Is(err, connector.ErrUnavailable) {
		t.Fatalf("Do() error = %v, want ErrUnavailable", err)
	}
	if attempts != 1 {
		t.Fatalf("mutation attempts = %d, want 1", attempts)
	}
}

func TestClientCancellationIsPreserved(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(time.Second)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, requestErr := client.Do(ctx, http.MethodGet, []string{"server"}, nil)
		result <- requestErr
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Do() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Do() did not stop after cancellation")
	}
}

func TestClientErrorDoesNotIncludeRequestURL(t *testing.T) {
	client, err := NewClient(Config{BaseURL: "https://dns.example.test", APIKey: "url-secret"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, []string{"invalid/part"}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("Do() error = %v, want safe invalid server error", err)
	}
	if strings.Contains(err.Error(), "url-secret") {
		t.Fatalf("Do() error leaked API key: %v", err)
	}
}
