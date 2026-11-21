package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/izenadns/izena-connector-contract/connector"
)

const maxProfileVersionLength = 100

type serverInfo struct {
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
}

// Probe reads the documented server metadata endpoint. The response decoder
// ignores additive upstream fields, while missing or incompatible identity
// information is classified without returning the upstream body.
func (c *Client) Probe(ctx context.Context) (connector.Profile, error) {
	response, err := c.Do(ctx, http.MethodGet, nil, nil)
	if err != nil {
		return connector.Profile{}, err
	}
	var info serverInfo
	if err := json.Unmarshal(response.Body, &info); err != nil {
		return connector.Profile{}, &connector.Error{Kind: connector.ErrMalformed, StatusCode: response.StatusCode, Code: "malformed_response"}
	}
	daemonType := strings.TrimSpace(info.DaemonType)
	if daemonType == "" {
		return connector.Profile{}, &connector.Error{Kind: connector.ErrMalformed, StatusCode: response.StatusCode, Code: "missing_daemon_type"}
	}
	if !strings.EqualFold(daemonType, "authoritative") {
		return connector.Profile{}, &connector.Error{Kind: connector.ErrUnsupported, StatusCode: response.StatusCode, Code: "unsupported_daemon"}
	}
	version := strings.TrimSpace(info.Version)
	major, err := versionMajor(version)
	if err != nil {
		return connector.Profile{}, &connector.Error{Kind: connector.ErrMalformed, StatusCode: response.StatusCode, Code: "invalid_version"}
	}
	if major != 5 {
		return connector.Profile{}, &connector.Error{Kind: connector.ErrUnsupported, StatusCode: response.StatusCode, Code: "unsupported_version"}
	}
	return connector.Profile{DaemonType: "Authoritative", Version: version}, nil
}

func versionMajor(version string) (int, error) {
	if len(version) > maxProfileVersionLength || strings.ContainsAny(version, "\r\n\x00") {
		return 0, connector.ErrMalformed
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" {
		return 0, connector.ErrMalformed
	}
	majorPart := version
	if dot := strings.IndexByte(version, '.'); dot >= 0 {
		if dot == len(version)-1 {
			return 0, connector.ErrMalformed
		}
		majorPart = version[:dot]
	}
	if majorPart == "" {
		return 0, connector.ErrMalformed
	}
	major, err := strconv.Atoi(majorPart)
	if err != nil || major < 1 {
		return 0, connector.ErrMalformed
	}
	return major, nil
}
