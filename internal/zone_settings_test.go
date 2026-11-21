package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/izenadns/izena-connector-contract/abi"
	"github.com/izenadns/izena-connector-contract/connector"
)

func TestPatchZoneSettingsRejectsInvalidFieldsBeforeHTTP(t *testing.T) {
	client := &Client{exchange: func(context.Context, abi.HTTPRequest) (Response, error) {
		t.Fatal("unexpected upstream request")
		return Response{}, nil
	}}
	invalid, increase, empty := "INVALID", "INCREASE", ""
	for _, patch := range []connector.ZoneSettingsPatch{
		{Set: map[string]connector.SettingValue{"unknown": {String: &increase}}},
		{Set: map[string]connector.SettingValue{soaEditAPIKey: {String: &invalid}}},
		{Set: map[string]connector.SettingValue{soaEditAPIKey: {String: &empty}}},
		{Set: map[string]connector.SettingValue{soaEditAPIKey: {String: &increase}}, Reset: []string{soaEditAPIKey}},
		{Reset: []string{soaEditKey, soaEditKey}},
	} {
		if err := client.PatchZoneSettings(t.Context(), "example.test.", patch); !errors.Is(err, connector.ErrValidation) {
			t.Fatalf("PatchZoneSettings() = %v, want validation failure", err)
		}
	}
	if err := client.PatchZoneSettings(t.Context(), "example.test.", connector.ZoneSettingsPatch{}); err != nil {
		t.Fatalf("empty patch: %v", err)
	}
}
