package internal

import (
	"context"
	"maps"
	"net/http"
	"strings"

	"github.com/izenadns/izena-connector-contract/abi"
	"github.com/izenadns/izena-connector-contract/connector"
)

const (
	providerID    = "powerdns-authoritative"
	providerName  = "PowerDNS Authoritative"
	baseURLKey    = "base_url"
	serverIDKey   = "server_id"
	credentialKey = "api_key"
	caBundleKey   = "ca_bundle_pem"
)

// Provider adapts the PowerDNS HTTP client to Izena's connector contract.
type Provider struct {
	newClient func(Config) (*Client, error)
}

func NewProvider(newClient func(Config) (*Client, error)) *Provider {
	return &Provider{newClient: newClient}
}

func (*Provider) Describe() connector.Description {
	return connector.Description{
		ID:   providerID,
		Name: providerName,
		ConnectionFields: []connector.ConnectionField{
			{Key: baseURLKey, Label: "API base URL", URL: true, MaxLength: maxBaseURLLength,
				Placeholder: "https://host:8081", Help: "PowerDNS API origin. Omit /api/v1.", Required: true},
			{Key: serverIDKey, Label: "Server id", Default: defaultServerID, MaxLength: maxServerIDLength, Required: true},
			{Key: credentialKey, Label: "API key", MaxLength: 4096, Required: true, Secret: true,
				Editable: true, Help: "Sent as X-API-Key and stored write-only."},
			{Key: caBundleKey, Label: "CA bundle", MaxLength: 65536, WriteOnly: true, Multiline: true, Editable: true,
				Placeholder: "-----BEGIN CERTIFICATE-----", Help: "Use this only for a private CA.",
				ClearLabel: "Use system trust", ClearDescription: "Clear the stored private CA bundle and verify using the system trust store."},
		},
	}
}

func (p *Provider) Manifest() abi.Manifest {
	return abi.Manifest{
		Description: p.Describe(),
		HTTP: abi.HTTPBinding{
			URLSetting: baseURLKey, CASetting: caBundleKey,
			Credentials: []abi.HTTPHeaderCredential{{Header: "X-API-Key", SecretField: credentialKey}},
		},
	}
}

func (*Provider) PrepareSettings(_ context.Context, settings map[string]string) (connector.PreparedSettings, error) {
	normalized, err := normalizeSettings(settings)
	if err != nil {
		return connector.PreparedSettings{}, err
	}
	if _, err := validatedServerID(normalized[serverIDKey]); err != nil {
		return connector.PreparedSettings{}, err
	}
	return connector.PreparedSettings{Settings: normalized, TargetKey: normalized[baseURLKey] + "\n" + normalized[serverIDKey]}, nil
}

// GuestClient constructs the provider API path before invoking the host transport.
func GuestClient(settings map[string]string, allowed func(abi.HTTPRequest) bool, exchange func(context.Context, abi.HTTPRequest) (Response, error)) (*Client, error) {
	id, err := validatedServerID(settings[serverIDKey])
	if err != nil {
		return nil, err
	}
	return &Client{exchange: func(ctx context.Context, request abi.HTTPRequest) (Response, error) {
		if !allowed(request) {
			return Response{}, connector.ErrValidation
		}
		request.Headers = http.Header{"Accept": {"application/json"}}
		if len(request.Body) != 0 {
			request.Headers.Set("Content-Type", "application/json")
		}
		request.Parts = append([]string{"api", "v1", "servers", id}, request.Parts...)
		return exchange(ctx, request)
	}}, nil
}

func normalizeSettings(settings map[string]string) (map[string]string, error) {
	baseURL, err := NormalizeBaseURL(strings.TrimSpace(settings[baseURLKey]))
	if err != nil {
		return nil, err
	}
	normalized := maps.Clone(settings)
	normalized[baseURLKey] = baseURL
	normalized[serverIDKey] = strings.TrimSpace(normalized[serverIDKey])
	if normalized[caBundleKey] == "" {
		delete(normalized, caBundleKey)
	}
	return normalized, nil
}

func (p *Provider) Connect(config connector.ConnectionConfig) (connector.Client, error) {
	client, err := p.newClient(powerDNSConfig(config))
	if err != nil {
		return nil, err
	}
	return client, nil
}

func powerDNSConfig(config connector.ConnectionConfig) Config {
	return Config{
		BaseURL:     config.Settings[baseURLKey],
		ServerID:    config.Settings[serverIDKey],
		APIKey:      config.Secrets[credentialKey],
		CABundlePEM: config.Settings[caBundleKey],
	}
}

var _ connector.Provider = (*Provider)(nil)
