package internal

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestProviderUsesNormalizedSettingsAndConnectionSecret(t *testing.T) {
	const key = "fixture-key"
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/proxy/api/v1/servers/fixture" || r.Header.Get("X-API-Key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"daemon_type":"authoritative","version":"5.1.0"}`))
	}))
	defer upstream.Close()

	var provider connector.Provider = NewProvider(NewClient)
	raw := map[string]string{baseURLKey: upstream.URL + "/proxy/", serverIDKey: "fixture"}
	prepared, err := provider.PrepareSettings(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	settings := prepared.Settings
	if settings[baseURLKey] != upstream.URL+"/proxy" || raw[baseURLKey] != upstream.URL+"/proxy/" {
		t.Fatal("normalization must preserve the proxy prefix and leave input unchanged")
	}
	client, err := provider.Connect(connector.ConnectionConfig{
		Settings: settings,
		Secrets:  map[string]string{credentialKey: key},
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("client construction contacted the upstream server")
	}
	profile, err := client.Probe(t.Context())
	if err != nil || profile.DaemonType != "Authoritative" || profile.Version != "5.1.0" || requests.Load() != 1 {
		t.Fatalf("Probe() = %+v, %v, %d requests", profile, err, requests.Load())
	}
}
