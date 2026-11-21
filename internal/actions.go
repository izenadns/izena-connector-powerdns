package internal

import (
	"context"
	"net/http"
)

func (c *Client) RectifyZone(ctx context.Context, zoneID string) error {
	return c.doZoneAction(ctx, zoneID, "rectify")
}

func (c *Client) NotifyZone(ctx context.Context, zoneID string) error {
	return c.doZoneAction(ctx, zoneID, "notify")
}

func (c *Client) AxfrZone(ctx context.Context, zoneID string) error {
	return c.doZoneAction(ctx, zoneID, "axfr-retrieve")
}

func (c *Client) doZoneAction(ctx context.Context, zoneID, action string) error {
	if err := validateZoneID(zoneID); err != nil {
		return err
	}
	_, err := c.doWithQueryLimitMode(ctx, http.MethodPut, []string{"zones", zoneID, action}, nil, nil, maxResponseBytes, true)
	return err
}
