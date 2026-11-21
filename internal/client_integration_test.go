//go:build integration

package internal

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/izenadns/izena-connector-contract/connector"
)

func TestPowerDNSFixtureDNSSECAndRectify(t *testing.T) {
	baseURL := os.Getenv("IZENA_PDNS_URL")
	apiKey := os.Getenv("IZENA_PDNS_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Fatal("IZENA_PDNS_URL and IZENA_PDNS_API_KEY are required for the PowerDNS fixture")
	}
	client, err := NewClient(Config{BaseURL: baseURL, ServerID: "localhost", APIKey: apiKey, ActionTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.Probe(t.Context()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	zoneID := fmt.Sprintf("pr018-%d.example.", time.Now().UnixNano())
	if _, err := client.CreateZone(context.Background(), connector.ZoneCreateInput{Name: zoneID, Kind: "native", Settings: map[string][]string{"nameservers": {"ns1." + zoneID}}}); err != nil {
		t.Fatalf("CreateZone() error = %v", err)
	}
	t.Cleanup(func() { _ = client.DeleteZone(context.Background(), zoneID) })
	zone, err := client.GetZone(t.Context(), zoneID)
	if err != nil || zone.Capabilities == nil || !zone.Capabilities.WriteRRsets || !zone.Capabilities.EditSOA || !zone.Capabilities.RecordComments || !zone.Capabilities.RecordDisabling {
		t.Fatalf("SQLite zone capabilities = %+v, %v", zone.Capabilities, err)
	}
	for _, test := range []struct {
		requestedType string
		returnedType  string
		content       string
	}{
		{requestedType: "TYPE1", returnedType: "A", content: "192.0.2.1"},
		{requestedType: "TYPE65280", returnedType: "TYPE65280", content: `\# 4 01020304`},
	} {
		t.Run(test.requestedType, func(t *testing.T) {
			name := "numeric." + zoneID
			if err := client.ReplaceRRset(t.Context(), zoneID, connector.RRsetReplaceInput{
				Name: name, Type: test.requestedType, TTL: 300, Records: []connector.Record{{Content: test.content}},
			}); err != nil {
				t.Fatalf("ReplaceRRset() error = %v", err)
			}
			rrset, err := client.GetRRset(t.Context(), zoneID, name, test.requestedType)
			if err != nil {
				t.Fatalf("GetRRset() error = %v", err)
			}
			if rrset.Name != name || rrset.Type != test.returnedType || rrset.TTL != 300 || len(rrset.Records) != 1 || rrset.Records[0].Content != test.content {
				t.Fatalf("rrset = %+v", rrset)
			}
		})
	}
	status, err := client.GetDNSSEC(context.Background(), zoneID)
	if err != nil || status.Enabled {
		t.Fatalf("initial DNSSEC status = %+v, error = %v", status, err)
	}
	if err := client.SetDNSSEC(context.Background(), zoneID, true); err != nil {
		t.Fatalf("SetDNSSEC(true) error = %v", err)
	}
	status, err = client.GetDNSSEC(context.Background(), zoneID)
	if err != nil || !status.Enabled || status.Active == nil || !*status.Active {
		t.Fatalf("secured DNSSEC status = %+v, error = %v", status, err)
	}
	if len(status.Keys) == 0 {
		t.Fatalf("secured DNSSEC keys = %+v, want PowerDNS public key metadata", status.Keys)
	}
	if err := client.RectifyZone(context.Background(), zoneID); err != nil {
		t.Fatalf("RectifyZone() error = %v", err)
	}
	if err := client.SetDNSSEC(context.Background(), zoneID, false); err != nil {
		t.Fatalf("SetDNSSEC(false) error = %v", err)
	}
	status, err = client.GetDNSSEC(context.Background(), zoneID)
	if err != nil || status.Enabled {
		t.Fatalf("unsecured DNSSEC status = %+v, error = %v", status, err)
	}
}

func TestPowerDNSFixtureNotifyAndAXFR(t *testing.T) {
	primaryURL := os.Getenv("IZENA_PDNS_PRIMARY_URL")
	secondaryURL := os.Getenv("IZENA_PDNS_SECONDARY_URL")
	apiKey := os.Getenv("IZENA_PDNS_API_KEY")
	if primaryURL == "" || secondaryURL == "" || apiKey == "" {
		t.Fatal("IZENA_PDNS_PRIMARY_URL, IZENA_PDNS_SECONDARY_URL and IZENA_PDNS_API_KEY are required for action fixtures")
	}
	primary, err := NewClient(Config{BaseURL: primaryURL, ServerID: "localhost", APIKey: apiKey, ActionTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("primary NewClient() error = %v", err)
	}
	secondary, err := NewClient(Config{BaseURL: secondaryURL, ServerID: "localhost", APIKey: apiKey, ActionTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("secondary NewClient() error = %v", err)
	}
	zoneID := fmt.Sprintf("pr018-actions-%d.example.", time.Now().UnixNano())
	if _, err := primary.CreateZone(context.Background(), connector.ZoneCreateInput{Name: zoneID, Kind: "primary", Settings: map[string][]string{"nameservers": {"ns1." + zoneID}}}); err != nil {
		t.Fatalf("primary CreateZone() error = %v", err)
	}
	t.Cleanup(func() { _ = primary.DeleteZone(context.Background(), zoneID) })
	if err := primary.NotifyZone(context.Background(), zoneID); err != nil {
		t.Fatalf("NotifyZone() error = %v", err)
	}
	primaryIP := os.Getenv("IZENA_PDNS_PRIMARY_IP")
	if primaryIP == "" {
		primaryIP = "10.253.0.10"
	}
	if _, err := secondary.CreateZone(context.Background(), connector.ZoneCreateInput{Name: zoneID, Kind: "secondary", Settings: map[string][]string{"transfer_primaries": {primaryIP + ":5353"}}}); err != nil {
		t.Fatalf("secondary CreateZone() error = %v", err)
	}
	t.Cleanup(func() { _ = secondary.DeleteZone(context.Background(), zoneID) })
	if err := secondary.AxfrZone(context.Background(), zoneID); err != nil {
		t.Fatalf("AxfrZone() error = %v", err)
	}
}

func TestPowerDNSFixtureSOASerialPolicies(t *testing.T) {
	baseURL, apiKey := os.Getenv("IZENA_PDNS_URL"), os.Getenv("IZENA_PDNS_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Fatal("IZENA_PDNS_URL and IZENA_PDNS_API_KEY are required for the PowerDNS fixture")
	}
	client, err := NewClient(Config{BaseURL: baseURL, APIKey: apiKey})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	zoneID := fmt.Sprintf("soa-policy-%d.example.", time.Now().UnixNano())
	if _, err := client.CreateZone(ctx, connector.ZoneCreateInput{Name: zoneID, Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.DeleteZone(context.WithoutCancel(ctx), zoneID) })
	increase, serve, defaultPolicy := "INCREASE", "NONE", "DEFAULT"
	if err := client.PatchZoneSettings(ctx, zoneID, connector.ZoneSettingsPatch{
		Set: map[string]connector.SettingValue{
			soaEditAPIKey: {String: &increase},
			soaEditKey:    {String: &serve},
		},
	}); err != nil {
		t.Fatal(err)
	}
	checkPolicy := func(key, want string) {
		t.Helper()
		settings, err := client.GetZoneSettings(ctx, zoneID)
		if err != nil {
			t.Fatal(err)
		}
		value, present := settings.Values[key]
		if want == "" && present || want != "" && (!present || value.String == nil || *value.String != want) {
			t.Fatalf("unexpected value for %s, want %q", key, want)
		}
	}
	checkPolicy(soaEditAPIKey, increase)
	checkPolicy(soaEditKey, serve)
	before, err := client.GetZoneMetadata(ctx, zoneID)
	if err != nil || before.Serial == nil {
		t.Fatalf("initial metadata = %+v, %v", before, err)
	}
	if err := client.ReplaceRRset(ctx, zoneID, connector.RRsetReplaceInput{
		Name: "before-reset." + zoneID, Type: "A", TTL: 300, Records: []connector.Record{{Content: "192.0.2.1"}},
	}); err != nil {
		t.Fatal(err)
	}
	increased, err := client.GetZoneMetadata(ctx, zoneID)
	if err != nil || increased.Serial == nil || *increased.Serial != *before.Serial+1 {
		t.Fatalf("INCREASE produced metadata %+v, %v", increased, err)
	}
	if err := client.PatchZoneSettings(ctx, zoneID, connector.ZoneSettingsPatch{
		Set: map[string]connector.SettingValue{soaEditAPIKey: {String: &defaultPolicy}},
	}); err != nil {
		t.Fatal(err)
	}
	checkPolicy(soaEditAPIKey, defaultPolicy)
	checkPolicy(soaEditKey, serve)
	if err := client.PatchZoneSettings(ctx, zoneID, connector.ZoneSettingsPatch{Reset: []string{soaEditAPIKey}}); err != nil {
		t.Fatal(err)
	}
	checkPolicy(soaEditAPIKey, "")
	checkPolicy(soaEditKey, serve)
	if err := client.ReplaceRRset(ctx, zoneID, connector.RRsetReplaceInput{
		Name: "after-reset." + zoneID, Type: "A", TTL: 300, Records: []connector.Record{{Content: "192.0.2.2"}},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := client.GetZoneMetadata(ctx, zoneID)
	if err != nil || after.Serial == nil || *after.Serial != *increased.Serial {
		t.Fatalf("reset policy produced metadata %+v, %v", after, err)
	}
	if err := client.PatchZoneSettings(ctx, zoneID, connector.ZoneSettingsPatch{Reset: []string{soaEditKey}}); err != nil {
		t.Fatal(err)
	}
	checkPolicy(soaEditKey, "")
}

func TestPowerDNSFixtureReadOnlyCapabilities(t *testing.T) {
	baseURL, apiKey := os.Getenv("IZENA_PDNS_BIND_URL"), os.Getenv("IZENA_PDNS_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Fatal("IZENA_PDNS_BIND_URL and IZENA_PDNS_API_KEY are required for the BIND fixture")
	}
	client, err := NewClient(Config{BaseURL: baseURL, APIKey: apiKey})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := client.Capabilities(t.Context())
	if err != nil || len(catalog.ZoneKinds) != 0 {
		t.Fatalf("BIND catalog = %+v, %v", catalog, err)
	}
	zone, err := client.GetZone(t.Context(), "read-only.example.")
	if err != nil || len(zone.RRsets) == 0 || zone.Capabilities == nil {
		t.Fatalf("BIND zone = %+v, %v", zone, err)
	}
	caps := zone.Capabilities
	if caps.WriteRRsets || caps.EditSOA || caps.RecordComments || caps.RecordDisabling || len(caps.UpdateZoneKinds) != 0 {
		t.Fatalf("BIND zone advertised writes: %+v", caps)
	}
}
