package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestDiscoveryReportsConnectionCatalogAndZoneApplicability(t *testing.T) {
	base := "/api/v1/servers/localhost"
	mux := http.NewServeMux()
	mux.HandleFunc(base, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"daemon_type":"authoritative","version":"5.1.0"}`))
	})
	mux.HandleFunc(base+"/config", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"launch","value":"gsqlite3"}]`))
	})
	tests := []struct {
		name    string
		kind    string
		masters []string
		inspect bool
		actions []connector.ZoneAction
	}{
		{"native", "Native", nil, true, []connector.ZoneAction{connector.ActionRectify}},
		{"primary", "Master", nil, true, []connector.ZoneAction{connector.ActionRectify, connector.ActionNotify}},
		{"secondary", "Slave", []string{"192.0.2.53"}, true, []connector.ZoneAction{connector.ActionAXFR}},
		{"without-primaries", "Slave", []string{}, false, nil},
	}
	for _, test := range tests {
		id := test.name + ".example."
		mux.HandleFunc(base+"/zones/"+id, func(w http.ResponseWriter, _ *http.Request) {
			response := map[string]any{"id": id, "name": id, "kind": test.kind, "masters": test.masters, "rrsets": []any{}}
			if test.inspect {
				response["dnssec"] = false
			}
			_ = json.NewEncoder(w).Encode(response)
		})
	}
	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	client, err := NewClient(Config{BaseURL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	server, err := client.Capabilities(t.Context())
	if err != nil || server.Provider != providerID || server.RecordModel != connector.RecordModelRRsets || len(server.ZoneKinds) != 3 ||
		!slices.Contains(server.RecordTypes, "AAAA") || !server.CustomRecordTypes ||
		!server.DNSSEC.Inspect || !server.DNSSEC.KeyMetadata || server.DNSSEC.Signing != connector.SigningUnknown || len(server.Actions) != 3 {
		t.Fatalf("Capabilities() = %+v, %v", server, err)
	}
	secondary := server.ZoneKinds[2]
	if secondary.ID != "secondary" || len(secondary.Fields) != 1 ||
		secondary.Fields[0].Key != zoneTransferPrimariesKey || !secondary.Fields[0].Required {
		t.Fatalf("secondary creation fields = %+v", secondary.Fields)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			zone, err := client.GetZone(t.Context(), test.name+".example.")
			caps := zone.Capabilities
			if err != nil || caps == nil || caps.DNSSEC.Inspect != test.inspect ||
				caps.DNSSEC.KeyMetadata != test.inspect || !caps.WriteRRsets || !caps.EditSOA ||
				!caps.RecordComments || !caps.RecordDisabling || !slices.Contains(caps.ManagedRecordTypes, "DNSKEY") ||
				!slices.Equal(caps.RecordTypes, server.RecordTypes) || !slices.Equal(caps.Actions, test.actions) {
				t.Fatalf("GetZone() capabilities = %+v, %v", caps, err)
			}
			metadata, err := client.GetZoneMetadata(t.Context(), test.name+".example.")
			if err != nil || !slices.Equal(metadata.Actions, caps.Actions) {
				t.Fatalf("GetZoneMetadata() actions = %v, %v; want %v", metadata.Actions, err, caps.Actions)
			}
		})
	}
}

func TestDiscoveryDisablesWritesWhenBackendCannotBeConfirmed(t *testing.T) {
	const base = "/api/v1/servers/localhost"
	for _, test := range []struct {
		name   string
		status int
		config string
	}{
		{"BIND", http.StatusOK, `[{"name":"launch","value":"bind"}]`},
		{"mixed", http.StatusOK, `[{"name":"launch","value":"gsqlite3, bind"}]`},
		{"unknown", http.StatusOK, `[{"name":"launch","value":"remote"}]`},
		{"missing launch", http.StatusOK, `[]`},
		{"unavailable", http.StatusForbidden, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(base, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"daemon_type":"authoritative","version":"5.1.0"}`))
			})
			mux.HandleFunc(base+"/config", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.config))
			})
			mux.HandleFunc(base+"/zones/example.test.", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"id":"example.test.","name":"example.test.","kind":"Master","dnssec":false,"rrsets":[],"soa_edit_api":"DEFAULT"}`))
			})
			upstream := httptest.NewServer(mux)
			t.Cleanup(upstream.Close)
			client, err := NewClient(Config{BaseURL: upstream.URL})
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := client.Capabilities(t.Context())
			if err != nil || len(catalog.ZoneKinds) != 0 || catalog.CustomRecordTypes {
				t.Fatalf("Capabilities() = %+v, %v", catalog, err)
			}
			zone, err := client.GetZone(t.Context(), "example.test.")
			caps := zone.Capabilities
			if err != nil || zone.ID != "example.test." || caps == nil {
				t.Fatalf("GetZone() = %+v, %v", zone, err)
			}
			if caps.WriteRRsets || caps.EditSOA || caps.RecordComments || caps.RecordDisabling ||
				len(caps.Settings) != 0 || len(caps.UpdateZoneKinds) != 0 ||
				!caps.DNSSEC.Inspect || caps.DNSSEC.Signing != connector.SigningUnsupported ||
				!slices.Equal(caps.Actions, []connector.ZoneAction{connector.ActionNotify}) {
				t.Fatalf("read-only zone capabilities = %+v", caps)
			}
		})
	}
}

func TestLMDBCommentsFollowPowerDNSVersion(t *testing.T) {
	const base = "/api/v1/servers/localhost"
	for _, test := range []struct {
		version  string
		comments bool
	}{
		{"5.0.0", false},
		{"5.1.0", true},
	} {
		t.Run(test.version, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(base, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"daemon_type": "authoritative", "version": test.version})
			})
			mux.HandleFunc(base+"/config", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`[{"name":"launch","value":"lmdb"}]`))
			})
			mux.HandleFunc(base+"/zones/example.test.", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"id":"example.test.","name":"example.test.","kind":"Native","rrsets":[]}`))
			})
			upstream := httptest.NewServer(mux)
			t.Cleanup(upstream.Close)
			client, err := NewClient(Config{BaseURL: upstream.URL})
			if err != nil {
				t.Fatal(err)
			}
			zone, err := client.GetZone(t.Context(), "example.test.")
			caps := zone.Capabilities
			if err != nil || caps == nil || !caps.WriteRRsets || caps.RecordComments != test.comments {
				t.Fatalf("LMDB zone capabilities = %+v, %v", caps, err)
			}
		})
	}
}
