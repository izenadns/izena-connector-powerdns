package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/izenadns/izena-connector-contract/connector"
)

const (
	zoneNameserversKey       = "nameservers"
	zoneTransferPrimariesKey = "transfer_primaries"
)

func (c *Client) Capabilities(ctx context.Context) (connector.ServerCapabilities, error) {
	if _, err := c.Probe(ctx); err != nil {
		return connector.ServerCapabilities{}, err
	}
	capabilities := connector.ServerCapabilities{
		Provider:    providerID,
		RecordModel: connector.RecordModelRRsets,
		DNSSEC:      connector.DNSSECCapabilities{Inspect: true, KeyMetadata: true, Signing: connector.SigningUnsupported},
		Actions:     []connector.ZoneAction{connector.ActionNotify, connector.ActionAXFR},
	}
	if c.backendFeatures(ctx).write {
		capabilities.ZoneKinds = zoneKindOptions()
		capabilities.RecordTypes = creatableRecordTypes()
		capabilities.CustomRecordTypes = true
		capabilities.DNSSEC.Signing = connector.SigningUnknown
		capabilities.Actions = append([]connector.ZoneAction{connector.ActionRectify}, capabilities.Actions...)
	}
	return capabilities, nil
}

type backendFeatures struct {
	write    bool
	comments bool
}

// PowerDNS reports the backend configuration for the server, not the
// backend serving a particular zone. Only advertise features common to all
// configured backends. An unavailable or unknown configuration still allows
// the DNS data to be inspected.
func (c *Client) backendFeatures(ctx context.Context) backendFeatures {
	response, err := c.Do(ctx, http.MethodGet, []string{"config"}, nil)
	if err != nil {
		return backendFeatures{}
	}
	var settings []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(response.Body, &settings); err != nil {
		return backendFeatures{}
	}
	for _, setting := range settings {
		if setting.Name == "launch" {
			return launchFeatures(setting.Value)
		}
	}
	return backendFeatures{}
}

func launchFeatures(launch string) backendFeatures {
	backends := strings.FieldsFunc(launch, func(char rune) bool { return char == ',' || unicode.IsSpace(char) })
	if len(backends) == 0 {
		return backendFeatures{}
	}
	features := backendFeatures{write: true, comments: true}
	for _, instance := range backends {
		backend, _, _ := strings.Cut(instance, ":")
		switch backend {
		case "gmysql", "gpgsql", "gsqlite3", "godbc":
		case "lmdb":
			// LMDB comments require a separate version check.
			features.comments = false
		default:
			return backendFeatures{}
		}
	}
	return features
}

func (c *Client) zoneBackendFeatures(ctx context.Context) backendFeatures {
	features := c.backendFeatures(ctx)
	if features.write && !features.comments {
		// LMDB gained RRset comments in PowerDNS 5.1. Generic SQL backends
		// support comments on both supported versions.
		profile, err := c.Probe(ctx)
		if err == nil {
			_, remainder, _ := strings.Cut(strings.TrimPrefix(profile.Version, "v"), ".")
			minor, _, _ := strings.Cut(remainder, ".")
			version, err := strconv.Atoi(minor)
			features.comments = err == nil && version >= 1
		}
	}
	return features
}

func zoneCapabilities(kind string, wire zoneWire, features backendFeatures) *connector.ZoneCapabilities {
	capabilities := &connector.ZoneCapabilities{
		ManagedRecordTypes: []string{"CDNSKEY", "CDS", "DS", "DLV", "DNSKEY", "KEY", "NSEC", "NSEC3", "NSEC3PARAM", "NXT", "RRSIG", "SIG", "TA"},
		DNSSEC:             connector.DNSSECCapabilities{Signing: connector.SigningUnsupported},
	}
	if wire.DNSSEC != nil {
		capabilities.DNSSEC.Inspect = true
		capabilities.DNSSEC.KeyMetadata = true
	}
	if !features.write {
		for _, action := range zoneActions(kind, wire.TransferPrimaries) {
			if action != connector.ActionRectify {
				capabilities.Actions = append(capabilities.Actions, action)
			}
		}
		return capabilities
	}

	capabilities.Actions = zoneActions(kind, wire.TransferPrimaries)
	capabilities.UpdateZoneKinds = []string{"native", "primary"}
	if kind == "secondary" {
		capabilities.UpdateZoneKinds = append(capabilities.UpdateZoneKinds, "secondary")
	}
	capabilities.RecordTypes = creatableRecordTypes()
	capabilities.CustomRecordTypes = true
	capabilities.WriteRRsets = true
	capabilities.EditSOA = true
	capabilities.RecordComments = features.comments
	capabilities.RecordDisabling = true
	if wire.DNSSEC != nil {
		// Writable storage does not prove that keys can be created or removed.
		capabilities.DNSSEC.Signing = connector.SigningUnknown
	}
	for _, field := range soaSettingFields() {
		if field.Key == soaEditAPIKey && wire.SOAEditAPI != nil || field.Key == soaEditKey && wire.SOAEdit != nil {
			capabilities.Settings = append(capabilities.Settings, field)
		}
	}
	return capabilities
}

func zoneKindOptions() []connector.ZoneKindOption {
	nameservers := connector.ZoneCreationField{
		Key: zoneNameserversKey, Label: "Nameservers (optional)",
		Description: "Enter fully qualified names separated by spaces or commas.",
		Placeholder: "ns1.example.test. ns2.example.test.",
	}
	primaries := connector.ZoneCreationField{
		Key: zoneTransferPrimariesKey, Label: "Transfer primaries (required)",
		Description: "Enter IP addresses separated by spaces or commas. Append a port when needed.",
		Placeholder: "192.0.2.53", Required: true,
	}
	return []connector.ZoneKindOption{
		{ID: "native", Label: "Native", Fields: []connector.ZoneCreationField{nameservers}},
		{ID: "primary", Label: "Primary", Fields: []connector.ZoneCreationField{nameservers}},
		{ID: "secondary", Label: "Secondary", Fields: []connector.ZoneCreationField{primaries}},
	}
}

// Common named types for the general editor. PowerDNS also accepts other
// presentation-format types. SOA and managed DNSSEC types have dedicated flows.
func creatableRecordTypes() []string {
	return []string{
		"A", "AAAA", "CNAME", "NS", "MX", "SRV", "TXT", "CAA",
		"PTR", "DNAME", "NAPTR", "SVCB", "HTTPS", "URI", "TLSA", "SSHFP",
	}
}

func zoneActions(kind string, transferPrimaries *[]string) []connector.ZoneAction {
	switch kind {
	case "native":
		return []connector.ZoneAction{connector.ActionRectify}
	case "primary":
		return []connector.ZoneAction{connector.ActionRectify, connector.ActionNotify}
	case "secondary":
		if transferPrimaries != nil && len(*transferPrimaries) > 0 {
			return []connector.ZoneAction{connector.ActionAXFR}
		}
	}
	return []connector.ZoneAction{}
}
