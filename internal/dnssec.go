package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/izenadns/izena-connector-contract/connector"
)

type cryptokeyWire struct {
	ID        *int64    `json:"id"`
	KeyType   string    `json:"keytype"`
	Active    *bool     `json:"active"`
	Published *bool     `json:"published"`
	DNSKEY    *string   `json:"dnskey"`
	DS        *[]string `json:"ds"`
	Algorithm *string   `json:"algorithm"`
	Bits      *int64    `json:"bits"`
}

type dnssecUpdateWire struct {
	DNSSEC bool `json:"dnssec"`
}

func (c *Client) SetDNSSEC(ctx context.Context, zoneID string, enabled bool) error {
	if err := validateZoneID(zoneID); err != nil {
		return err
	}
	body, _ := json.Marshal(dnssecUpdateWire{DNSSEC: enabled})
	_, err := c.Do(ctx, http.MethodPut, []string{"zones", zoneID}, body)
	return err
}

func (c *Client) GetDNSSEC(ctx context.Context, zoneID string) (connector.DNSSEC, error) {
	if err := validateZoneID(zoneID); err != nil {
		return connector.DNSSEC{}, err
	}
	query := url.Values{}
	query.Set("rrsets", "false")
	response, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", zoneID}, query, nil, maxResponseBytes)
	if err != nil {
		return connector.DNSSEC{}, err
	}
	var zone zoneWire
	if err := json.Unmarshal(response.Body, &zone); err != nil {
		return connector.DNSSEC{}, malformedZone(response.StatusCode, "malformed_dnssec_zone")
	}
	validated, err := decodeZone(zone, response.StatusCode, zoneID, false)
	if err != nil {
		return connector.DNSSEC{}, err
	}
	if zone.DNSSEC == nil {
		return connector.DNSSEC{}, &connector.Error{Kind: connector.ErrUnsupported, StatusCode: response.StatusCode, Code: "dnssec_unavailable"}
	}
	status := connector.DNSSEC{Enabled: validated.DNSSEC != nil && *validated.DNSSEC}
	if !status.Enabled {
		return status, nil
	}
	// PowerDNS deliberately omits privatekey from the collection endpoint. We
	// decode only the public fields needed by the inspector, so private key
	// material can never be reflected accidentally in the project-owned model.
	keysResponse, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", zoneID, "cryptokeys"}, nil, nil, maxResponseBytes)
	if err != nil {
		return connector.DNSSEC{}, err
	}
	var keys []cryptokeyWire
	if err := json.Unmarshal(keysResponse.Body, &keys); err != nil || keys == nil {
		return connector.DNSSEC{}, &connector.Error{Kind: connector.ErrMalformed, StatusCode: keysResponse.StatusCode, Code: "malformed_cryptokeys"}
	}
	status.Keys = make([]connector.DNSSECKey, 0, len(keys))
	active := false
	for _, key := range keys {
		mapped, ok := mapCryptokey(key)
		if !ok {
			return connector.DNSSEC{}, &connector.Error{Kind: connector.ErrMalformed, StatusCode: keysResponse.StatusCode, Code: "malformed_cryptokeys"}
		}
		status.Keys = append(status.Keys, mapped)
		active = active || mapped.Active
	}
	status.Active = &active
	return status, nil
}

// DNSSECKey contains only public key metadata. DS and DNSKEY values are
// public records; privatekey is intentionally not part of either this type or
// cryptokeyWire.
func mapCryptokey(wire cryptokeyWire) (connector.DNSSECKey, bool) {
	keyType := strings.ToLower(strings.TrimSpace(wire.KeyType))
	if wire.ID == nil || *wire.ID < 0 || (keyType != "ksk" && keyType != "zsk" && keyType != "csk") || wire.Active == nil || wire.Published == nil || wire.DNSKEY == nil {
		return connector.DNSSECKey{}, false
	}
	dnskey := strings.TrimSpace(*wire.DNSKEY)
	if dnskey == "" || len(dnskey) > 65535 || (keyType != "zsk" && wire.DS == nil) {
		return connector.DNSSECKey{}, false
	}
	keyTag := dnskeyKeyTag(dnskey)
	if keyTag == nil {
		return connector.DNSSECKey{}, false
	}
	key := connector.DNSSECKey{
		ID:        *wire.ID,
		KeyType:   keyType,
		Active:    *wire.Active,
		Published: *wire.Published,
		DNSKEY:    dnskey,
		KeyTag:    *keyTag,
	}
	if wire.Algorithm != nil {
		algorithm := strings.TrimSpace(*wire.Algorithm)
		if algorithm != "" && len(algorithm) <= 64 {
			key.Algorithm = &algorithm
		}
	}
	if wire.Bits != nil && *wire.Bits >= 0 && *wire.Bits <= 65535 {
		bits := int32(*wire.Bits)
		key.Bits = &bits
	}
	if wire.DS != nil {
		if len(*wire.DS) > 8 {
			return connector.DNSSECKey{}, false
		}
		key.DS = make([]string, len(*wire.DS))
		for index, value := range *wire.DS {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 2048 {
				return connector.DNSSECKey{}, false
			}
			key.DS[index] = value
		}
	}
	return key, true
}

// dnskeyKeyTag computes the RFC 4034 key tag from PowerDNS' DNSKEY value.
// PowerDNS does not expose a separate keytag field on the cryptokey endpoint.
func dnskeyKeyTag(value string) *int32 {
	fields := strings.Fields(value)
	if len(fields) < 4 {
		return nil
	}
	flags, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil
	}
	protocol, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return nil
	}
	algorithm, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.Join(fields[3:], ""))
	if err != nil || len(publicKey) == 0 {
		return nil
	}
	wire := make([]byte, 4+len(publicKey))
	wire[0] = byte(flags >> 8)
	wire[1] = byte(flags & 0xff)
	wire[2] = byte(protocol)
	wire[3] = byte(algorithm)
	copy(wire[4:], publicKey)
	var sum uint32
	for index := 0; index+1 < len(wire); index += 2 {
		sum += uint32(wire[index])<<8 | uint32(wire[index+1])
	}
	if len(wire)%2 == 1 {
		sum += uint32(wire[len(wire)-1]) << 8
	}
	sum = (sum & 0xffff) + (sum >> 16)
	sum += sum >> 16
	tag := int32(sum & 0xffff)
	return &tag
}
