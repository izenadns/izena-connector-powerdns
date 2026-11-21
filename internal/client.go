// Package pdns contains the project-owned PowerDNS Authoritative adapter.
//
// The package deliberately exposes no PowerDNS-generated types.  Server
// configuration is validated and converted into one origin-pinned client so
// credentials cannot accidentally be sent to a different host.
package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/izenadns/izena-connector-contract/abi"
	"github.com/izenadns/izena-connector-contract/connector"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultTimeout       = 10 * time.Second
	defaultActionTimeout = 60 * time.Second
	minimumTLSVersion    = tls.VersionTLS12
	defaultServerID      = "localhost"
	maxServerIDLength    = 255
	maxBaseURLLength     = 2048
	maxCABundlePEMLength = 1024 * 1024
)

const (
	maxResponseBytes = 2 * 1024 * 1024
	// Large zone responses can contain a complete RRset accepted by the 16 MiB
	// request-body limit plus the PowerDNS zone envelope and JSON headroom.
	maxLargeResponseBytes = 32 * 1024 * 1024
)

// Response contains a bounded PowerDNS response body. Callers must treat the
// body as adapter data and never include it in user-facing errors.
type Response struct {
	StatusCode int
	Body       []byte
}

// Config is the minimum persisted server material required to create an
// origin-pinned client. APIKey is optional while constructing a client so
// URL/TLS validation can happen before decrypting a stored credential.
type Config struct {
	BaseURL             string
	ServerID            string
	APIKey              string
	CABundlePEM         string
	Timeout             time.Duration
	ActionTimeout       time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	Metrics             Observer
	Tracer              trace.Tracer
}

// Observer receives bounded PowerDNS operation outcomes. Implementations
// must not use server, zone or record values as metric labels.
type Observer interface {
	ObserveDNSProvider(provider, operation, statusClass string, duration time.Duration)
}

// Client is a PowerDNS client bound to one validated origin and server ID.
type Client struct {
	baseURL       url.URL
	serverID      string
	apiKey        string
	timeout       time.Duration
	actionTimeout time.Duration
	http          *http.Client
	metrics       Observer
	tracer        trace.Tracer
	exchange      func(context.Context, abi.HTTPRequest) (Response, error)
}

// NormalizeBaseURL validates and normalizes a persisted server base URL. It
// preserves a reverse-proxy path prefix while rejecting URL features that
// could change the origin or make request composition ambiguous.
func NormalizeBaseURL(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxBaseURLLength {
		return "", connector.ErrInvalidServerURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", connector.ErrInvalidServerURL
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", connector.ErrInvalidServerURL
	}
	if u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", connector.ErrInvalidServerURL
	}
	if u.RawPath != "" && u.RawPath != u.EscapedPath() {
		return "", connector.ErrInvalidServerURL
	}
	if strings.Contains(strings.ToLower(u.RawPath), "%2f") {
		return "", connector.ErrInvalidServerURL
	}
	segments := strings.Split(u.Path, "/")
	for index, segment := range segments {
		if segment == "" && index != 0 && index != len(segments)-1 {
			return "", connector.ErrInvalidServerURL
		}
		if segment == "." || segment == ".." || strings.ContainsRune(segment, '\\') {
			return "", connector.ErrInvalidServerURL
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// NewClient validates server configuration and creates an HTTP client whose
// redirect, proxy and TLS behavior is fixed by the application. It never
// disables certificate verification.
func NewClient(config Config) (*Client, error) {
	base, err := NormalizeBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	serverID, err := validatedServerID(config.ServerID)
	if err != nil {
		return nil, err
	}
	if len(config.CABundlePEM) > maxCABundlePEMLength {
		return nil, connector.ErrInvalidServerTLS
	}
	tlsConfig, err := tlsConfig(config.CABundlePEM)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, connector.ErrInvalidServerURL
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	actionTimeout := config.ActionTimeout
	if actionTimeout <= 0 {
		actionTimeout = defaultActionTimeout
	}
	transportTimeout := timeout
	if actionTimeout > transportTimeout {
		transportTimeout = actionTimeout
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: transportTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   transportTimeout,
		ResponseHeaderTimeout: transportTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
	}
	client := &Client{
		baseURL:       *u,
		serverID:      serverID,
		apiKey:        config.APIKey,
		timeout:       timeout,
		actionTimeout: actionTimeout,
		http: &http.Client{
			Transport: transport,
			// Request contexts carry the normal or action-specific deadline.
			// Keeping Client.Timeout unset lets long-running administrative
			// actions use their distinct bounded timeout.
			Timeout: 0,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		metrics: config.Metrics,
		tracer:  config.Tracer,
	}
	client.exchange = client.ExchangeHTTP
	return client, nil
}

func validatedServerID(serverID string) (string, error) {
	if serverID == "" {
		serverID = defaultServerID
	}
	if len(serverID) > maxServerIDLength || strings.TrimSpace(serverID) == "" || strings.ContainsAny(serverID, "\r\n") {
		return "", connector.ErrInvalidServer
	}
	if strings.ContainsAny(serverID, "\\?#") {
		return "", connector.ErrInvalidServer
	}
	for _, segment := range strings.Split(serverID, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", connector.ErrInvalidServer
		}
	}
	return serverID, nil
}

func tlsConfig(caBundlePEM string) (*tls.Config, error) {
	if caBundlePEM == "" {
		return &tls.Config{MinVersion: minimumTLSVersion}, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(caBundlePEM)) {
		return nil, connector.ErrInvalidServerTLS
	}
	return &tls.Config{MinVersion: minimumTLSVersion, RootCAs: pool}, nil
}

// endpoint builds only adapter-owned API paths. Path segments are escaped
// individually and the persisted origin/path prefix is never replaced.
func (c *Client) endpoint(parts ...string) (*url.URL, error) {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\?#\r\n") {
			return nil, connector.ErrInvalidServer
		}
	}
	u := c.baseURL
	prefix := strings.TrimRight(u.Path, "/")
	escapedPrefix := strings.TrimRight(u.EscapedPath(), "/")
	serverEscaped := url.PathEscape(c.serverID)
	u.Path = prefix + "/api/v1/servers/" + c.serverID
	u.RawPath = escapedPrefix + "/api/v1/servers/" + serverEscaped
	if len(parts) > 0 {
		for _, part := range parts {
			u.Path += "/" + part
			u.RawPath += "/" + url.PathEscape(part)
		}
	}
	// path.Clean is only used as an invariant check; it must never rewrite the
	// persisted prefix or a server identifier.
	if path.Clean(u.Path) != u.Path {
		return nil, connector.ErrInvalidServerURL
	}
	return &u, nil
}

// Do executes an origin-pinned request with bounded response reads and no
// automatic retry. The caller controls mutation semantics by choosing the
// method; this adapter never repeats a request.
func (c *Client) Do(ctx context.Context, method string, parts []string, body []byte) (Response, error) {
	return c.doWithQueryLimit(ctx, method, parts, nil, body, maxResponseBytes)
}

func (c *Client) doWithQueryLimit(ctx context.Context, method string, parts []string, query url.Values, body []byte, maxBytes int) (Response, error) {
	return c.doWithQueryLimitMode(ctx, method, parts, query, body, maxBytes, false)
}

func (c *Client) doWithQueryLimitMode(ctx context.Context, method string, parts []string, query url.Values, body []byte, maxBytes int, action bool) (Response, error) {
	call := abi.HTTPRequest{
		Method: method, Parts: parts, Query: query, Body: body,
		Limit: maxBytes, Action: action,
	}
	response, err := c.exchange(ctx, call)
	if err != nil {
		return Response{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Response{}, statusError(response.StatusCode, response.Body)
	}
	return response, nil
}

// ExchangeHTTP applies the bound connection's network and TLS policy. Only
// relative PowerDNS API paths cross the guest boundary.
func (c *Client) ExchangeHTTP(ctx context.Context, request abi.HTTPRequest) (Response, error) {
	method, parts, query, body, maxBytes := request.Method, request.Parts, request.Query, request.Body, request.Limit
	if maxBytes < 1 || maxBytes > maxLargeResponseBytes {
		return Response{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_http_exchange"}
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return Response{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_http_method"}
	}
	timeout := c.timeout
	if request.Action {
		timeout = c.actionTimeout
	}

	operation := operationLabel(method, parts)
	started := time.Now()
	statusClass := "error"
	var span trace.Span
	if c.tracer != nil {
		ctx, span = c.tracer.Start(ctx, "pdns "+operation, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.String("izena.pdns.operation", operation)))
	}
	defer func() {
		if c.metrics != nil {
			c.metrics.ObserveDNSProvider(providerID, operation, statusClass, time.Since(started))
		}
		if span != nil {
			if statusClass != "2xx" {
				span.SetStatus(codes.Error, "")
			}
			span.End()
		}
	}()
	u, err := c.endpoint(parts...)
	if err != nil {
		return Response{}, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	requestContext := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > timeout {
		requestContext, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, &connector.Error{Kind: connector.ErrInvalidServerURL}
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	response, err := c.http.Do(req)
	if err != nil {
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return Response{}, &connector.Error{Kind: connector.ErrTimeout, Code: "timeout", Cause: context.DeadlineExceeded}
		}
		if errors.Is(requestContext.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return Response{}, &connector.Error{Kind: connector.ErrUnavailable, Code: "canceled", Cause: context.Canceled}
		}
		if isTLSFailure(err) {
			return Response{}, &connector.Error{Kind: connector.ErrTLS, Code: "tls_failure"}
		}
		return Response{}, &connector.Error{Kind: connector.ErrUnavailable, Code: "unavailable"}
	}
	statusClass = pdnsStatusClass(response.StatusCode)
	defer func() {
		_ = response.Body.Close()
	}()
	limited := io.LimitReader(response.Body, int64(maxBytes)+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		statusClass = "error"
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return Response{}, &connector.Error{Kind: connector.ErrTimeout, Code: "timeout", Cause: context.DeadlineExceeded}
		}
		if errors.Is(err, context.Canceled) {
			return Response{}, &connector.Error{Kind: connector.ErrUnavailable, Code: "canceled", Cause: context.Canceled}
		}
		var timeoutErr net.Error
		if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
			return Response{}, &connector.Error{Kind: connector.ErrTimeout, Code: "timeout"}
		}
		return Response{}, &connector.Error{Kind: connector.ErrUnavailable, Code: "read_failed"}
	}
	if len(responseBody) > maxBytes {
		statusClass = "error"
		return Response{}, &connector.Error{Kind: connector.ErrResponseTooLarge, StatusCode: response.StatusCode, Code: "response_too_large"}
	}
	if c.apiKey != "" && (response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		key := strings.Join(strings.Fields(c.apiKey), " ")
		if bytes.Contains(responseBody, []byte(c.apiKey)) || (key != "" && strings.Contains(responseDetail(responseBody), key)) {
			responseBody = nil
		}
	}
	return Response{StatusCode: response.StatusCode, Body: responseBody}, nil
}

func operationLabel(method string, parts []string) string {
	family := "unknown"
	if len(parts) > 0 && parts[0] != "" {
		family = strings.ToLower(parts[0])
	}
	return strings.ToUpper(method) + " " + metricSafeLabel(family, 32)
}

func metricSafeLabel(value string, max int) string {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\r\n") {
		return "unknown"
	}
	return value
}

func pdnsStatusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

func statusError(status int, body []byte) *connector.Error {
	detail := responseDetail(body)
	switch status {
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return &connector.Error{Kind: connector.ErrTimeout, StatusCode: status, Code: "timeout", Detail: detail}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &connector.Error{Kind: connector.ErrAuthentication, StatusCode: status, Code: "authentication_failed", Detail: detail}
	case http.StatusNotFound:
		return &connector.Error{Kind: connector.ErrNotFound, StatusCode: status, Code: "not_found", Detail: detail}
	case http.StatusConflict:
		return &connector.Error{Kind: connector.ErrConflict, StatusCode: status, Code: "conflict", Detail: detail}
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return &connector.Error{Kind: connector.ErrValidation, StatusCode: status, Code: "validation_failed", Detail: detail}
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return &connector.Error{Kind: connector.ErrRedirect, StatusCode: status, Code: "redirect_rejected", Detail: detail}
	default:
		return &connector.Error{Kind: connector.ErrUnavailable, StatusCode: status, Code: "unavailable", Detail: detail}
	}
}

const maxResponseDiagnosticLength = 512

func responseDetail(body []byte) string {
	var response struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &response) != nil || response.Error == "" {
		return ""
	}
	detail := strings.Join(append([]string{response.Error}, response.Errors...), "; ")
	detail = strings.Join(strings.Fields(detail), " ")
	if strings.ContainsRune(detail, '\x00') {
		return ""
	}
	if len(detail) > maxResponseDiagnosticLength {
		end := maxResponseDiagnosticLength - len("...")
		for !utf8.RuneStart(detail[end]) {
			end--
		}
		detail = detail[:end] + "..."
	}
	return detail
}

func isTLSFailure(err error) bool {
	var certErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCertErr x509.CertificateInvalidError
	var verificationErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	return errors.As(err, &certErr) || errors.As(err, &hostnameErr) || errors.As(err, &invalidCertErr) || errors.As(err, &verificationErr) || errors.As(err, &recordErr)
}
