package internal

import (
	"net/http"

	"github.com/izenadns/izena-connector-contract/abi"
)

func allowedRequest(call abi.Request, request abi.HTTPRequest) bool {
	method, parts := request.Method, request.Parts
	zone := len(parts) >= 2 && parts[0] == "zones" && parts[1] == call.ZoneID && call.ZoneID != ""
	zoneResource := zone && len(parts) == 2
	collection := len(parts) == 1 && parts[0] == "zones"
	switch call.Operation {
	case abi.Probe:
		return method == http.MethodGet && len(parts) == 0
	case abi.Capabilities:
		return method == http.MethodGet && (len(parts) == 0 || len(parts) == 1 && parts[0] == "config")
	case abi.GetZone:
		return method == http.MethodGet && (zoneResource || len(parts) == 0 || len(parts) == 1 && parts[0] == "config")
	case abi.ListZones:
		return method == http.MethodGet && collection
	case abi.GetZoneMetadata, abi.GetRRset, abi.GetZoneSettings:
		return method == http.MethodGet && zoneResource
	case abi.GetDNSSEC:
		return method == http.MethodGet && (zoneResource || (zone && len(parts) == 3 && parts[2] == "cryptokeys"))
	case abi.SetDNSSEC, abi.PatchZoneSettings:
		return method == http.MethodPut && zoneResource
	case abi.CreateZone:
		return method == http.MethodPost && collection
	case abi.UpdateZone:
		return zoneResource && (method == http.MethodGet || method == http.MethodPut)
	case abi.DeleteZone:
		return method == http.MethodDelete && zoneResource
	case abi.ReplaceRRset, abi.DeleteRRset:
		return method == http.MethodPatch && zoneResource
	case abi.RectifyZone:
		return method == http.MethodPut && zone && len(parts) == 3 && parts[2] == "rectify"
	case abi.NotifyZone:
		return method == http.MethodPut && zone && len(parts) == 3 && parts[2] == "notify"
	case abi.AxfrZone:
		return method == http.MethodPut && zone && len(parts) == 3 && parts[2] == "axfr-retrieve"
	default:
		return false
	}
}
