package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestCreateZoneMapsPublicKindAndReturnsCurrentZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/servers/localhost/zones" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["kind"] != "Master" || body["name"] != "example.org." {
			t.Fatalf("request body = %#v", body)
		}
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Master","rrsets":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	zone, err := client.CreateZone(context.Background(), connector.ZoneCreateInput{Name: "example.org.", Kind: "primary", Settings: map[string][]string{"nameservers": {"ns1.example.org."}}})
	if err != nil {
		t.Fatalf("CreateZone() error = %v", err)
	}
	if zone.Kind != "primary" || zone.ID != "example.org." {
		t.Fatalf("zone = %+v", zone)
	}
}

func TestCreateSecondaryZoneMapsNameserversToMasters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		masters, ok := body["masters"].([]interface{})
		if !ok || len(masters) != 1 || masters[0] != "192.0.2.53" {
			t.Fatalf("request body = %#v", body)
		}
		if _, present := body["nameservers"]; present {
			t.Fatalf("secondary request unexpectedly included nameservers: %#v", body)
		}
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Slave","rrsets":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.CreateZone(context.Background(), connector.ZoneCreateInput{Name: "example.org.", Kind: "secondary", Settings: map[string][]string{"transfer_primaries": {"192.0.2.53"}}}); err != nil {
		t.Fatalf("CreateZone() error = %v", err)
	}
}

func TestUpdateAndDeleteZoneUseOneRequestEach(t *testing.T) {
	methods := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		if request.Method == http.MethodPut {
			var body map[string]interface{}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode update request: %v", err)
			}
			if body["kind"] != "Master" {
				t.Fatalf("update request body = %#v", body)
			}
			if _, present := body["nameservers"]; present {
				t.Fatalf("update request unexpectedly included nameservers: %#v", body)
			}
			_, _ = writer.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	kind := "primary"
	if _, err := client.UpdateZone(context.Background(), "example.org.", connector.ZoneUpdateInput{Kind: kind}); err != nil {
		t.Fatalf("UpdateZone() error = %v", err)
	}
	if err := client.DeleteZone(context.Background(), "example.org."); err != nil {
		t.Fatalf("DeleteZone() error = %v", err)
	}
	if len(methods) != 2 || methods[0] != http.MethodPut || methods[1] != http.MethodDelete {
		t.Fatalf("methods = %v", methods)
	}
}
