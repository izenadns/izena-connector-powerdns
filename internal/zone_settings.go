package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"

	"github.com/izenadns/izena-connector-contract/connector"
)

const (
	soaEditAPIKey = "soa_edit_api"
	soaEditKey    = "soa_edit"
)

func soaSettingFields() []connector.SettingField {
	return []connector.SettingField{
		{
			Key: soaEditAPIKey, Label: "SOA serial policy for API changes", Kind: connector.SettingEnum, Resettable: true,
			Options: []connector.SettingOption{
				{Value: "DEFAULT", Label: "Date-based serial"},
				{Value: "INCREASE", Label: "Increase by one"},
				{Value: "EPOCH", Label: "Unix timestamp"},
				{Value: "SOA-EDIT", Label: "Use serving policy"},
				{Value: "SOA-EDIT-INCREASE", Label: "Use serving policy with increment fallback"},
			},
		},
		{
			Key: soaEditKey, Label: "SOA serial policy when serving", Kind: connector.SettingEnum, Resettable: true,
			Options: []connector.SettingOption{
				{Value: "INCREMENT-WEEKS", Label: "Add weeks since Unix epoch"},
				{Value: "INCEPTION-EPOCH", Label: "Signature inception timestamp"},
				{Value: "INCEPTION-INCREMENT", Label: "Date-based signature inception"},
				{Value: "EPOCH", Label: "Unix timestamp"},
				{Value: "NONE", Label: "Disable serving policy"},
			},
		},
	}
}

func (c *Client) GetZoneSettings(ctx context.Context, zoneID string) (connector.ZoneSettings, error) {
	if err := validateZoneID(zoneID); err != nil {
		return connector.ZoneSettings{}, err
	}
	query := url.Values{"rrsets": {"false"}}
	response, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", zoneID}, query, nil, maxResponseBytes)
	if err != nil {
		return connector.ZoneSettings{}, err
	}
	var wire zoneWire
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return connector.ZoneSettings{}, malformedZone(response.StatusCode, "malformed_zone_settings")
	}
	if _, err := decodeZoneMetadata(wire.zoneMetadataWire, response.StatusCode, zoneID); err != nil {
		return connector.ZoneSettings{}, err
	}

	settings := connector.ZoneSettings{Values: make(map[string]connector.SettingValue)}
	for key, value := range map[string]*string{soaEditAPIKey: wire.SOAEditAPI, soaEditKey: wire.SOAEdit} {
		if value != nil && *value != "" {
			settings.Values[key] = connector.SettingValue{String: value}
		}
	}
	return settings, nil
}

func (c *Client) PatchZoneSettings(ctx context.Context, zoneID string, patch connector.ZoneSettingsPatch) error {
	if err := validateZoneID(zoneID); err != nil {
		return err
	}
	fields := soaSettingFields()
	settings := make(map[string]string, len(fields))
	for key, value := range patch.Set {
		if value.String == nil || value.Boolean != nil || value.Integer != nil || value.StringList != nil ||
			!slices.ContainsFunc(fields, func(field connector.SettingField) bool {
				return field.Key == key && slices.ContainsFunc(field.Options, func(option connector.SettingOption) bool {
					return option.Value == *value.String
				})
			}) {
			return connector.ErrValidation
		}
		settings[key] = *value.String
	}
	for _, key := range patch.Reset {
		if _, exists := settings[key]; exists || !slices.ContainsFunc(fields, func(field connector.SettingField) bool {
			return field.Key == key && field.Resettable
		}) {
			return connector.ErrValidation
		}
		settings[key] = ""
	}
	if len(settings) == 0 {
		return nil
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, http.MethodPut, []string{"zones", zoneID}, body)
	return err
}

var _ connector.ZoneSettingsOperations = (*Client)(nil)
