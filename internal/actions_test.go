package internal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestZoneActionsUseDocumentedPutEndpoints(t *testing.T) {
	paths := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", request.Method)
		}
		paths = append(paths, request.URL.Path)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, ActionTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	ctx := context.Background()
	if err := client.RectifyZone(ctx, "example.org."); err != nil {
		t.Fatalf("RectifyZone() error = %v", err)
	}
	if err := client.NotifyZone(ctx, "example.org."); err != nil {
		t.Fatalf("NotifyZone() error = %v", err)
	}
	if err := client.AxfrZone(ctx, "example.org."); err != nil {
		t.Fatalf("AxfrZone() error = %v", err)
	}
	want := []string{
		"/api/v1/servers/localhost/zones/example.org./rectify",
		"/api/v1/servers/localhost/zones/example.org./notify",
		"/api/v1/servers/localhost/zones/example.org./axfr-retrieve",
	}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
}

func TestZoneActionUsesDistinctActionTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(80 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, ActionTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.RectifyZone(context.Background(), "example.org."); !errors.Is(err, connector.ErrTimeout) {
		t.Fatalf("RectifyZone() error = %v, want timeout", err)
	}
}

func TestZoneActionMapsGatewayTimeoutToErrTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.RectifyZone(context.Background(), "example.org."); !errors.Is(err, connector.ErrTimeout) {
		t.Fatalf("RectifyZone() error = %v, want timeout", err)
	}
}
