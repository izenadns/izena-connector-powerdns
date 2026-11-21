package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/izenadns/izena-connector-contract/connector"
)

type zoneWire struct {
	zoneMetadataWire
	SOAEditAPI *string      `json:"soa_edit_api"`
	SOAEdit    *string      `json:"soa_edit"`
	RRsets     *[]rrsetWire `json:"rrsets"`
	DNSSEC     *bool        `json:"dnssec"`
}

type zoneMetadataWire struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	Serial            *int64    `json:"serial"`
	TransferPrimaries *[]string `json:"masters"`
}

func (c *Client) ListZones(ctx context.Context) ([]connector.Zone, error) {
	response, err := c.Do(ctx, http.MethodGet, []string{"zones"}, nil)
	if err != nil {
		return nil, err
	}
	var wire []zoneWire
	if err := json.Unmarshal(response.Body, &wire); err != nil || wire == nil {
		return nil, malformedZone(response.StatusCode, "malformed_zone_list")
	}
	result := make([]connector.Zone, 0, len(wire))
	for _, item := range wire {
		zone, err := decodeZone(item, response.StatusCode, "", false)
		if err != nil {
			return nil, err
		}
		result = append(result, zone)
	}
	return result, nil
}

func (c *Client) GetZone(ctx context.Context, id string) (connector.Zone, error) {
	if err := validateZoneID(id); err != nil {
		return connector.Zone{}, err
	}
	response, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", id}, nil, nil, maxLargeResponseBytes)
	if err != nil {
		return connector.Zone{}, err
	}
	var wire zoneWire
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return connector.Zone{}, malformedZone(response.StatusCode, "malformed_zone")
	}
	zone, err := decodeZone(wire, response.StatusCode, id, true)
	if err != nil {
		return connector.Zone{}, err
	}
	zone.Capabilities = zoneCapabilities(zone.Kind, wire, c.zoneBackendFeatures(ctx))
	return zone, nil
}

func (c *Client) GetZoneMetadata(ctx context.Context, id string) (connector.ZoneMetadata, error) {
	if err := validateZoneID(id); err != nil {
		return connector.ZoneMetadata{}, err
	}
	query := url.Values{}
	query.Set("rrsets", "false")
	response, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", id}, query, nil, maxResponseBytes)
	if err != nil {
		return connector.ZoneMetadata{}, err
	}
	var wire zoneMetadataWire
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return connector.ZoneMetadata{}, malformedZone(response.StatusCode, "malformed_zone_metadata")
	}
	return decodeZoneMetadata(wire, response.StatusCode, id)
}

func decodeZoneMetadata(wire zoneMetadataWire, status int, expectedID string) (connector.ZoneMetadata, error) {
	if !validText(wire.ID, 255) || (expectedID != "" && wire.ID != expectedID) {
		return connector.ZoneMetadata{}, malformedZone(status, "invalid_zone_id")
	}
	if !validText(wire.Name, 255) {
		return connector.ZoneMetadata{}, malformedZone(status, "invalid_zone_name")
	}
	kind := normalizeZoneKind(wire.Kind)
	if kind == "" {
		if strings.TrimSpace(wire.Kind) == "" {
			return connector.ZoneMetadata{}, malformedZone(status, "missing_zone_kind")
		}
		return connector.ZoneMetadata{}, &connector.Error{Kind: connector.ErrUnsupported, StatusCode: status, Code: "unsupported_zone_kind"}
	}
	if wire.Serial != nil && *wire.Serial < 0 {
		return connector.ZoneMetadata{}, malformedZone(status, "invalid_zone_serial")
	}
	return connector.ZoneMetadata{ID: wire.ID, Name: wire.Name, Kind: kind, Serial: wire.Serial, Actions: zoneActions(kind, wire.TransferPrimaries)}, nil
}

var _ connector.ZoneReader = (*Client)(nil)

func decodeZone(wire zoneWire, status int, expectedID string, requireRRsets bool) (connector.Zone, error) {
	metadata, err := decodeZoneMetadata(wire.zoneMetadataWire, status, expectedID)
	if err != nil {
		return connector.Zone{}, err
	}
	if wire.RRsets == nil && requireRRsets {
		return connector.Zone{}, malformedZone(status, "missing_rrsets")
	}
	rrsets := make([]connector.RRset, 0)
	if wire.RRsets != nil {
		rrsets = make([]connector.RRset, 0, len(*wire.RRsets))
		for _, value := range *wire.RRsets {
			mapped, err := decodeRRset(value, status)
			if err != nil {
				return connector.Zone{}, err
			}
			rrsets = append(rrsets, mapped)
		}
	}
	return connector.Zone{ID: metadata.ID, Name: metadata.Name, Kind: metadata.Kind, Serial: metadata.Serial, RRsets: rrsets, DNSSEC: wire.DNSSEC}, nil
}

func normalizeZoneKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "native":
		return "native"
	case "primary", "master":
		return "primary"
	case "secondary", "slave":
		return "secondary"
	default:
		return ""
	}
}

func validateZoneID(value string) error {
	if !validText(value, 255) || strings.ContainsAny(value, "/\\?#\r\n") {
		return &connector.Error{Kind: connector.ErrValidation, Code: "invalid_zone_id"}
	}
	return nil
}

func validText(value string, max int) bool {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	return utf8.RuneCountInString(value) <= max
}

func malformedZone(status int, code string) error {
	return &connector.Error{Kind: connector.ErrMalformed, StatusCode: status, Code: code}
}
