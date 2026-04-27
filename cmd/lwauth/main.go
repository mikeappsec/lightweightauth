// Command lwauth is the default LightweightAuth daemon. It bundles only
// the core builtins (jwt, apikey, rbac). To extend it with extra plugins,
// build your own binary that blank-imports your plugin packages — see
// pkg/lwauthd and the examples under lightweightauth-plugins/go/cmd/.
package main

import (
	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"

	"github.com/mikeappsec/lightweightauth/pkg/lwauthd"
)

func main() { lwauthd.Main() }
