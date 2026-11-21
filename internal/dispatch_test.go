package internal

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/izenadns/izena-connector-contract/abi"
	"github.com/izenadns/izena-connector-contract/connector"
)

func TestDispatchPowerDNSOperation(t *testing.T) {
	settings := map[string]string{baseURLKey: "https://dns.example.test/", serverIDKey: "fixture"}
	calls := 0
	exchange := func(_ context.Context, req abi.HTTPRequest) (Response, error) {
		calls++
		if req.Method != http.MethodGet || !slices.Equal(req.Parts, []string{"api", "v1", "servers", "fixture"}) {
			t.Fatal("unexpected upstream probe route")
		}
		return Response{StatusCode: http.StatusOK, Body: []byte(`{"daemon_type":"authoritative","version":"5.1.0"}`)}, nil
	}
	result, err := Dispatch(t.Context(), abi.Request{Operation: abi.Describe}, nil)
	manifest, ok := result.(abi.Manifest)
	if err != nil || !ok || manifest.Description.ID != providerID {
		t.Fatalf("Describe result = %+v, %v", result, err)
	}
	result, err = Dispatch(t.Context(), abi.Request{Operation: abi.PrepareSettings, Settings: settings}, nil)
	prepared, ok := result.(connector.PreparedSettings)
	if err != nil || !ok || prepared.TargetKey != "https://dns.example.test\nfixture" {
		t.Fatalf("PrepareSettings result = %+v, %v", result, err)
	}
	result, err = Dispatch(t.Context(), abi.Request{Operation: abi.Probe, Settings: settings}, exchange)
	if err != nil || result != (connector.Profile{DaemonType: "Authoritative", Version: "5.1.0"}) {
		t.Fatalf("Probe result = %+v, %v", result, err)
	}
	if _, err := Dispatch(t.Context(), abi.Request{
		Operation: abi.CreateZone, Settings: settings, Input: []byte("{"),
	}, exchange); !errors.Is(err, connector.ErrValidation) {
		t.Fatalf("malformed CreateZone input = %v, want validation error", err)
	}
	if _, err := Dispatch(t.Context(), abi.Request{
		Operation: "unknown_operation", Settings: settings,
	}, exchange); !errors.Is(err, connector.ErrUnsupported) {
		t.Fatalf("unknown operation = %v, want unsupported", err)
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d, want one probe request", calls)
	}
}
