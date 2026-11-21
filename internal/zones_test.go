package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestListZonesMapsPowerDNSResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/servers/localhost/zones" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		_, _ = writer.Write([]byte(`[{"id":"example.org.","name":"example.org.","kind":"Native","serial":12,"future":true}]`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	zones, err := client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	if len(zones) != 1 || zones[0].ID != "example.org." || zones[0].Kind != "native" || zones[0].Serial == nil || *zones[0].Serial != 12 {
		t.Fatalf("zones = %+v", zones)
	}
	if zones[0].RRsets == nil || len(zones[0].RRsets) != 0 {
		t.Fatalf("rrsets = %+v, want empty non-nil slice", zones[0].RRsets)
	}
}

func TestGetZoneMapsRRsetsRecordsAndComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/servers/localhost/config" {
			_, _ = writer.Write([]byte(`[{"name":"launch","value":"gsqlite3"}]`))
			return
		}
		if request.URL.Path != "/api/v1/servers/localhost/zones/example.org." {
			t.Fatalf("request path = %q", request.URL.Path)
		}
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Primary","serial":42,"rrsets":[{"name":"www.example.org.","type":"A","ttl":300,"records":[{"content":"192.0.2.1","disabled":false}],"comments":[{"content":"managed","account":"izena","modified_at":1700000000}]}]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	zone, err := client.GetZone(context.Background(), "example.org.")
	if err != nil {
		t.Fatalf("GetZone() error = %v", err)
	}
	if len(zone.RRsets) != 1 || len(zone.RRsets[0].Records) != 1 || len(zone.RRsets[0].Comments) != 1 {
		t.Fatalf("zone = %+v", zone)
	}
	if !zone.RRsets[0].Comments[0].ModifiedAt.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("modified_at = %v", zone.RRsets[0].Comments[0].ModifiedAt)
	}
}

func TestGetZoneMetadataDoesNotDecodeRRsets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("rrsets") != "false" {
			t.Fatalf("query = %s, want rrsets=false", request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Secondary","rrsets":[{"invalid":true}]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	metadata, err := client.GetZoneMetadata(context.Background(), "example.org.")
	if err != nil {
		t.Fatalf("GetZoneMetadata() error = %v", err)
	}
	if metadata.Kind != "secondary" || metadata.ID != "example.org." {
		t.Fatalf("metadata = %+v", metadata)
	}
}

func TestDirectZoneReadsRejectMismatchedResponseID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"other.example.","name":"other.example.","kind":"Native","dnssec":false,"rrsets":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetZone(t.Context(), "expected.example."); !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("GetZone() = %v, want malformed response", err)
	}
	if _, err := client.GetZoneMetadata(t.Context(), "expected.example."); !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("GetZoneMetadata() = %v, want malformed response", err)
	}
	if _, err := client.GetDNSSEC(t.Context(), "expected.example."); !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("GetDNSSEC() = %v, want malformed response", err)
	}
	if _, err := client.GetRRset(t.Context(), "expected.example.", "shared.expected.example.", "A"); !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("GetRRset() = %v, want malformed response", err)
	}
}

func TestZoneReadersAllowLargeResponses(t *testing.T) {
	content := strings.Repeat("x", 65535)
	records := make([]recordWire, 40)
	for index := range records {
		records[index] = recordWire{Content: content}
	}
	comments := []commentWire{}
	rrsets := []rrsetWire{{
		Name:     "www.example.org.",
		Type:     "TXT",
		TTL:      300,
		Records:  &records,
		Comments: &comments,
	}}
	body, err := json.Marshal(zoneWire{
		zoneMetadataWire: zoneMetadataWire{ID: "example.org.", Name: "example.org.", Kind: "Native"},
		RRsets:           &rrsets,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if len(body) <= maxResponseBytes {
		t.Fatalf("test response = %d bytes, want more than default response limit", len(body))
	}
	if len(body) >= maxLargeResponseBytes {
		t.Fatalf("test response = %d bytes, want less than large response limit", len(body))
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	rrset, err := client.GetRRset(context.Background(), "example.org.", "www.example.org.", "TXT")
	if err != nil {
		t.Fatalf("GetRRset() error = %v", err)
	}
	if len(rrset.Records) != len(records) {
		t.Fatalf("records = %d, want %d", len(rrset.Records), len(records))
	}
	zone, err := client.GetZone(context.Background(), "example.org.")
	if err != nil {
		t.Fatalf("GetZone() error = %v", err)
	}
	if len(zone.RRsets) != 1 || len(zone.RRsets[0].Records) != len(records) {
		t.Fatalf("zone RRsets = %+v, want one large RRset", zone.RRsets)
	}
}

func TestZoneReaderRejectsMalformedRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "missing identity", body: `[{"name":"example.org.","kind":"Native"}]`, want: connector.ErrMalformed},
		{name: "missing detail rrsets", body: `{"id":"example.org.","name":"example.org.","kind":"Native"}`, want: connector.ErrMalformed},
		{name: "missing record content", body: `{"id":"example.org.","name":"example.org.","kind":"Native","rrsets":[{"name":"@","type":"A","ttl":60,"records":[{"disabled":false}],"comments":[]}]}`, want: connector.ErrMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/v1/servers/localhost/zones" {
					_, _ = writer.Write([]byte(test.body))
					return
				}
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			if test.name == "missing identity" {
				_, err = client.ListZones(context.Background())
			} else {
				_, err = client.GetZone(context.Background(), "example.org.")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestZoneReaderClassifiesUnknownKindsAndToleratesAdditiveFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "unknown kind", body: `[{"id":"example.org.","name":"example.org.","kind":"FutureKind","new_field":true}]`, want: connector.ErrUnsupported},
		{name: "missing kind", body: `[{"id":"example.org.","name":"example.org.","new_field":true}]`, want: connector.ErrMalformed},
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
			_, err = client.ListZones(context.Background())
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestGetZoneRejectsNullRRsetCollections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","rrsets":[{"name":"@","type":"A","ttl":60,"records":null,"comments":[]}]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.GetZone(context.Background(), "example.org.")
	if !errors.Is(err, connector.ErrMalformed) {
		t.Fatalf("error = %v, want malformed", err)
	}
}

func TestZoneReadPreservesMultilineComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","rrsets":[{"name":"example.org.","type":"A","ttl":300,"records":[{"content":"192.0.2.1","disabled":false}],"comments":[{"content":"first\nsecond\r\nthird","account":"review\noperator","modified_at":1700000000}]}]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.GetZone(t.Context(), "example.org.")
	if err != nil {
		t.Fatal(err)
	}
	comment := zone.RRsets[0].Comments[0]
	if comment.Content != "first\nsecond\r\nthird" || comment.Account != "review\noperator" {
		t.Fatal("comment presentation was changed")
	}
}

func TestDecodeZoneRetainsLargeRRsetInventory(t *testing.T) {
	records := []recordWire{{Content: "192.0.2.1"}}
	comments := []commentWire{}
	rrsets := make([]rrsetWire, 10001)
	for index := range rrsets {
		rrsets[index] = rrsetWire{
			Name: "host" + strconv.Itoa(index) + ".example.org.",
			Type: "A", TTL: 300, Records: &records, Comments: &comments,
		}
	}
	zone, err := decodeZone(zoneWire{zoneMetadataWire: zoneMetadataWire{ID: "example.org.", Name: "example.org.", Kind: "Native"}, RRsets: &rrsets}, http.StatusOK, "example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(zone.RRsets) != len(rrsets) || zone.RRsets[10000].Name != "host10000.example.org." {
		t.Fatal("large zone inventory was truncated")
	}
}
