package executor

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

func logCodexNetworkRoute(scope, target string, cfg *config.Config, auth *cliproxyauth.Auth) {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return
	}
	route := resolveProxyRouteIdentity(cfg, auth)
	mode := route.logTag
	if mode == "" {
		mode = "direct-default"
	}
	origin := "direct-" + route.source
	if route.routeMode == routeModeString(proxyutil.ModeProxy) {
		mode = "proxy"
		origin = route.logTag
	}
	target = strings.TrimSpace(target)
	fields := log.Fields{
		"codex-net-scope":  scope,
		"codex-net-auth":   route.authID,
		"codex-net-target": target,
		"codex-net-mode":   mode,
		"codex-net-origin": origin,
	}
	if route.ipv6 != "" {
		fields["codex-net-ipv6"] = route.ipv6
	}
	log.WithFields(fields).Debugf("codex-net-mode=%s codex-net-origin=%s codex-net-scope=%s codex-net-auth=%s codex-net-target=%s", mode, origin, scope, route.authID, target)
}
