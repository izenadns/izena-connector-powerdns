package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestGetRRsetUsesPowerDNSFilters(t *testing.T) {
	const address = `{"name":"www.example.org.","type":"A","ttl":300,"records":[{"content":"192.0.2.1","disabled":false}],"comments":[]}`
	const private = `{"name":"www.example.org.","type":"TYPE65280","ttl":300,"records":[{"content":"\\# 4 01020304","disabled":false}],"comments":[]}`
	for _, test := range []struct {
		name          string
		requestedType string
		returnedType  string
		rrsets        string
		want          error
	}{
		{name: "mnemonic", requestedType: "A", returnedType: "A", rrsets: address},
		{name: "numeric alias", requestedType: "TYPE1", returnedType: "A", rrsets: address},
		{name: "private type", requestedType: "TYPE65280", returnedType: "TYPE65280", rrsets: private},
		{name: "absent", requestedType: "A", want: connector.ErrNotFound},
		{name: "different owner", requestedType: "A", rrsets: strings.ReplaceAll(address, "www.example.org.", "other.example.org."), want: connector.ErrNotFound},
		{name: "multiple rrsets", requestedType: "A", rrsets: address + "," + address, want: connector.ErrMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("rrset_name") != "www.example.org." || request.URL.Query().Get("rrset_type") != test.requestedType {
					t.Fatalf("query = %s", request.URL.RawQuery)
				}
				_, _ = writer.Write([]byte(`{"id":"example.org.","name":"example.org.","kind":"Native","rrsets":[` + test.rrsets + `]}`))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			rrset, err := client.GetRRset(context.Background(), "example.org.", "www.example.org.", test.requestedType)
			if !errors.Is(err, test.want) {
				t.Fatalf("GetRRset() error = %v, want %v", err, test.want)
			}
			if test.want != nil {
				return
			}
			if rrset.Name != "www.example.org." || rrset.Type != test.returnedType || len(rrset.Records) != 1 {
				t.Fatalf("rrset = %+v", rrset)
			}
		})
	}
}

func TestReplaceRRsetSendsOneCompleteReplacePatch(t *testing.T) {
	for _, test := range []struct {
		name string
		ttl  int64
	}{
		{name: "nonzero TTL", ttl: 300},
		{name: "zero TTL", ttl: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPatch || request.URL.Path != "/api/v1/servers/localhost/zones/example.org." {
					t.Fatalf("request = %s %s", request.Method, request.URL.Path)
				}
				var body struct {
					RRsets []struct {
						ChangeType string                `json:"changetype"`
						TTL        *int64                `json:"ttl"`
						Records    []recordWire          `json:"records"`
						Comments   []commentMutationWire `json:"comments"`
					} `json:"rrsets"`
				}
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if len(body.RRsets) != 1 || body.RRsets[0].ChangeType != "REPLACE" || body.RRsets[0].TTL == nil || *body.RRsets[0].TTL != test.ttl {
					t.Fatalf("request body = %+v", body)
				}
				if len(body.RRsets[0].Records) != 2 || body.RRsets[0].Records[1].Content != "192.0.2.2" {
					t.Fatalf("records = %+v", body.RRsets[0].Records)
				}
				if len(body.RRsets[0].Comments) != 1 || body.RRsets[0].Comments[0].ModifiedAt == nil {
					t.Fatalf("comments = %+v", body.RRsets[0].Comments)
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			if err := client.ReplaceRRset(context.Background(), "example.org.", connector.RRsetReplaceInput{
				Name: "www.example.org.", Type: "A", TTL: test.ttl,
				Records:  []connector.Record{{Content: "192.0.2.1"}, {Content: "192.0.2.2", Disabled: true}},
				Comments: []connector.Comment{{Content: "managed", Account: "izena", ModifiedAt: time.Unix(1700000000, 0).UTC()}},
			}); err != nil {
				t.Fatalf("ReplaceRRset() error = %v", err)
			}
		})
	}
}

func TestDeleteRRsetPatchContractOmitsReplaceFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string][]map[string]interface{}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(body["rrsets"]) != 1 {
			t.Fatalf("request body = %#v", body)
		}
		item := body["rrsets"][0]
		if item["changetype"] != "DELETE" || item["name"] != "www.example.org." || item["type"] != "A" {
			t.Fatalf("rrset patch = %#v", item)
		}
		if _, ok := item["ttl"]; ok {
			t.Fatalf("delete patch unexpectedly included ttl: %#v", item)
		}
		if _, ok := item["records"]; ok {
			t.Fatalf("delete patch unexpectedly included records: %#v", item)
		}
		comments, ok := item["comments"].([]interface{})
		if !ok || len(comments) != 0 {
			t.Fatalf("comments = %#v", item["comments"])
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.DeleteRRset(context.Background(), "example.org.", "www.example.org.", "A"); err != nil {
		t.Fatalf("DeleteRRset() error = %v", err)
	}
}
