package internal

import (
	"net/http"
	"testing"

	"github.com/izenadns/izena-connector-contract/abi"
)

func TestHTTPPolicyBindsRequestsToOperationAndZone(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation abi.Operation
		method    string
		parts     []string
		want      bool
	}{
		{"probe", abi.Probe, http.MethodGet, nil, true},
		{"zone read", abi.GetZone, http.MethodGet, []string{"zones", "target."}, true},
		{"other zone", abi.GetZone, http.MethodGet, []string{"zones", "other."}, false},
		{"read cannot write", abi.GetZone, http.MethodPut, []string{"zones", "target."}, false},
		{"DNSSEC keys", abi.GetDNSSEC, http.MethodGet, []string{"zones", "target.", "cryptokeys"}, true},
		{"unexpected action", abi.NotifyZone, http.MethodPut, []string{"zones", "target.", "rectify"}, false},
		{"expected action", abi.NotifyZone, http.MethodPut, []string{"zones", "target.", "notify"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := abi.Request{Operation: test.operation, ZoneID: "target."}
			request := abi.HTTPRequest{Method: test.method, Parts: test.parts}
			if got := allowedRequest(call, request); got != test.want {
				t.Fatalf("allowedRequest() = %t, want %t", got, test.want)
			}
		})
	}
}
