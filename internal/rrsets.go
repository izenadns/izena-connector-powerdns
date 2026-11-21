package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/izenadns/izena-connector-contract/abi"
	"github.com/izenadns/izena-connector-contract/connector"
)

type rrsetWire struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	TTL      int64          `json:"ttl"`
	Records  *[]recordWire  `json:"records"`
	Comments *[]commentWire `json:"comments"`
}

type recordWire struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type commentWire struct {
	Content    string `json:"content"`
	Account    string `json:"account"`
	ModifiedAt *int64 `json:"modified_at"`
}

type rrsetPatchWire struct {
	Name       string                `json:"name"`
	Type       string                `json:"type"`
	TTL        int64                 `json:"ttl"`
	ChangeType string                `json:"changetype"`
	Records    []recordWire          `json:"records"`
	Comments   []commentMutationWire `json:"comments"`
}

type commentMutationWire struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt *int64 `json:"modified_at,omitempty"`
}

type zoneRRsetPatchWire struct {
	RRsets []rrsetPatchWire `json:"rrsets"`
}

type rrsetDeleteWire struct {
	Name       string                `json:"name"`
	Type       string                `json:"type"`
	ChangeType string                `json:"changetype"`
	Comments   []commentMutationWire `json:"comments"`
}

type zoneRRsetDeleteWire struct {
	RRsets []rrsetDeleteWire `json:"rrsets"`
}

func (c *Client) GetRRset(ctx context.Context, zoneID, name, rrType string) (connector.RRset, error) {
	if err := validateZoneID(zoneID); err != nil {
		return connector.RRset{}, err
	}
	if !validText(name, 255) || !validText(rrType, 64) {
		return connector.RRset{}, &connector.Error{Kind: connector.ErrValidation, Code: "invalid_rrset_identity"}
	}
	query := url.Values{}
	query.Set("rrset_name", name)
	query.Set("rrset_type", rrType)
	response, err := c.doWithQueryLimit(ctx, http.MethodGet, []string{"zones", zoneID}, query, nil, maxLargeResponseBytes)
	if err != nil {
		return connector.RRset{}, err
	}
	var wire zoneWire
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return connector.RRset{}, malformedZone(response.StatusCode, "malformed_rrset")
	}
	zone, err := decodeZone(wire, response.StatusCode, zoneID, true)
	if err != nil {
		return connector.RRset{}, err
	}
	if len(zone.RRsets) > 1 {
		return connector.RRset{}, malformedZone(response.StatusCode, "multiple_filtered_rrsets")
	}
	// PowerDNS applies the type filter numerically and returns its canonical
	// spelling, so TYPE1 can be returned as A.
	if len(zone.RRsets) == 1 && strings.EqualFold(zone.RRsets[0].Name, name) {
		return zone.RRsets[0], nil
	}
	return connector.RRset{}, &connector.Error{Kind: connector.ErrNotFound, StatusCode: http.StatusNotFound, Code: "rrset_not_found"}
}

func (c *Client) ReplaceRRset(ctx context.Context, zoneID string, input connector.RRsetReplaceInput) error {
	if input.AutomaticTTL || len(input.Options) != 0 {
		return connector.ErrUnsupported
	}
	if err := validateZoneID(zoneID); err != nil {
		return err
	}
	body, _ := abi.Marshal(zoneRRsetPatchWire{RRsets: []rrsetPatchWire{{
		Name: input.Name, Type: input.Type, TTL: input.TTL, ChangeType: "REPLACE",
		Records: encodeMutationRecords(input.Records), Comments: encodeMutationComments(input.Comments),
	}}})
	_, err := c.Do(ctx, http.MethodPatch, []string{"zones", zoneID}, body)
	return err
}

func (c *Client) DeleteRRset(ctx context.Context, zoneID, name, rrType string) error {
	if err := validateZoneID(zoneID); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(rrType) == "" {
		return &connector.Error{Kind: connector.ErrValidation, Code: "invalid_rrset_identity"}
	}
	body, _ := abi.Marshal(zoneRRsetDeleteWire{RRsets: []rrsetDeleteWire{{
		Name: name, Type: rrType, ChangeType: "DELETE", Comments: []commentMutationWire{},
	}}})
	_, err := c.Do(ctx, http.MethodPatch, []string{"zones", zoneID}, body)
	return err
}

func encodeMutationRecords(records []connector.Record) []recordWire {
	result := make([]recordWire, len(records))
	for index, record := range records {
		result[index] = recordWire(record)
	}
	return result
}

func encodeMutationComments(comments []connector.Comment) []commentMutationWire {
	result := make([]commentMutationWire, len(comments))
	for index, comment := range comments {
		result[index] = commentMutationWire{Content: comment.Content, Account: comment.Account}
		if !comment.ModifiedAt.IsZero() {
			modifiedAt := comment.ModifiedAt.Unix()
			result[index].ModifiedAt = &modifiedAt
		}
	}
	return result
}

func decodeRRset(wire rrsetWire, status int) (connector.RRset, error) {
	if !validText(wire.Name, 255) || !validText(wire.Type, 64) {
		return connector.RRset{}, malformedZone(status, "invalid_rrset_identity")
	}
	if wire.TTL < 0 || wire.TTL > 2147483647 || wire.Records == nil || wire.Comments == nil {
		return connector.RRset{}, malformedZone(status, "invalid_rrset_fields")
	}
	if len(*wire.Records) > 10000 || len(*wire.Comments) > 10000 {
		return connector.RRset{}, malformedZone(status, "too_many_rrset_values")
	}
	records := make([]connector.Record, 0, len(*wire.Records))
	for _, record := range *wire.Records {
		if !validText(record.Content, 65535) {
			return connector.RRset{}, malformedZone(status, "invalid_record_content")
		}
		records = append(records, connector.Record(record))
	}
	comments := make([]connector.Comment, 0, len(*wire.Comments))
	for _, comment := range *wire.Comments {
		if !validCommentText(comment.Content, 65535) || !validCommentText(comment.Account, 255) || comment.ModifiedAt == nil {
			return connector.RRset{}, malformedZone(status, "invalid_comment")
		}
		comments = append(comments, connector.Comment{Content: comment.Content, Account: comment.Account, ModifiedAt: time.Unix(*comment.ModifiedAt, 0).UTC()})
	}
	return connector.RRset{Name: wire.Name, Type: wire.Type, TTL: wire.TTL, Records: records, Comments: comments}, nil
}

// Comments are presentation text, and PowerDNS accepts embedded line breaks.
// Keep the DNS identity validator strict without making valid comments unreadable.
func validCommentText(value string, maxBytes int) bool {
	return utf8.ValidString(value) && len(value) <= maxBytes && !strings.ContainsRune(value, '\x00')
}
