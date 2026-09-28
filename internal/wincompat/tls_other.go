//go:build !windows

package wincompat

import "crypto/tls"

func TLSConfig() *tls.Config { return nil }
