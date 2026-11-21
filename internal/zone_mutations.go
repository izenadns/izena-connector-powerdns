package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/izenadns/izena-connector-contract/connector"
)

type zoneCreateWire struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Nameservers []string `json:"nameservers,omitempty"`
	Masters     []string `json:"masters,omitempty"`
}

type zoneUpdateWire struct {
	Kind string `json:"kind"`
}

func (c *Client) CreateZone(ctx context.Context, input connector.ZoneCreateInput) (connector.Zone, error) {
	kind, err := upstreamZoneKind(input.Kind)
	if err != nil {
		return connector.Zone{}, err
	}
	settings, err := zoneCreationValues(input.Kind, input.Settings)
	if err != nil {
		return connector.Zone{}, err
	}
	settings.Name, settings.Kind = input.Name, kind
	body, _ := json.Marshal(settings)
	response, err := c.Do(ctx, http.MethodPost, []string{"zones"}, body)
	if err != nil {
		return connector.Zone{}, err
	}
	var wire zoneWire
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return connector.Zone{}, malformedZone(response.StatusCode, "malformed_created_zone")
	}
	return decodeZone(wire, response.StatusCode, "", true)
}

func (c *Client) UpdateZone(ctx context.Context, id string, input connector.ZoneUpdateInput) (connector.ZoneUpdateResult, error) {
	if err := validateZoneID(id); err != nil {
		return connector.ZoneUpdateResult{}, err
	}
	kind, err := upstreamZoneKind(input.Kind)
	if err != nil {
		return connector.ZoneUpdateResult{}, err
	}
	if input.Kind == "secondary" {
		current, err := c.GetZoneMetadata(ctx, id)
		if err != nil {
			return connector.ZoneUpdateResult{}, err
		}
		if current.Kind != input.Kind {
			return connector.ZoneUpdateResult{Previous: &current}, &connector.Error{
				Kind:   connector.ErrUnsupported,
				Code:   "secondary_conversion_unsupported",
				Detail: "Converting to secondary requires transfer primaries. Create a secondary with transfer primaries or configure the existing zone directly in PowerDNS.",
			}
		}
		// Reapplying the kind of an existing secondary can reset its transfers.
		return connector.ZoneUpdateResult{Previous: &current}, nil
	}
	body, _ := json.Marshal(zoneUpdateWire{Kind: kind})
	_, err = c.Do(ctx, http.MethodPut, []string{"zones", id}, body)
	return connector.ZoneUpdateResult{Attempted: true}, err
}

func zoneCreationValues(kind string, settings map[string][]string) (zoneCreateWire, error) {
	key := zoneNameserversKey
	if kind == "secondary" {
		key = zoneTransferPrimariesKey
	}
	values, present := settings[key]
	if len(settings) != 0 && (len(settings) != 1 || !present) ||
		len(values) > 32 || kind == "secondary" && len(values) == 0 {
		return zoneCreateWire{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_zone_settings"}
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 || strings.ContainsAny(value, " \t\x00\r\n/\\?#") {
			return zoneCreateWire{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_zone_setting_value"}
		}
		if kind != "secondary" {
			value = strings.TrimSuffix(value, ".") + "."
			for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
				if label == "" || utf8.RuneCountInString(label) > 63 {
					return zoneCreateWire{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_nameserver"}
				}
			}
			if utf8.RuneCountInString(value) > 255 {
				return zoneCreateWire{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_nameserver"}
			}
		}
		normalized = append(normalized, value)
	}
	if kind == "secondary" {
		return zoneCreateWire{Masters: normalized}, nil
	}
	return zoneCreateWire{Nameservers: normalized}, nil
}

func (c *Client) DeleteZone(ctx context.Context, id string) error {
	if err := validateZoneID(id); err != nil {
		return err
	}
	_, err := c.Do(ctx, http.MethodDelete, []string{"zones", id}, nil)
	return err
}

func upstreamZoneKind(value string) (string, error) {
	switch value {
	case "native":
		return "Native", nil
	case "primary":
		return "Master", nil
	case "secondary":
		return "Slave", nil
	default:
		return "", &connector.Error{Kind: connector.ErrValidation, Code: "invalid_zone_kind"}
	}
}

var _ connector.ZoneMutator = (*Client)(nil)
