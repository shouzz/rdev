//go:build windows

package wincompat

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net"
	"net/http"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ISRG Root X1, from https://letsencrypt.org/certs/isrgrootx1.pem.
// DER SHA256: 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6.
//
//go:embed isrgrootx1.pem
var publicRootPEM []byte

var legacyRoots *x509.CertPool

func init() {
	if windows.RtlGetVersion().MajorVersion >= 10 {
		return
	}
	// Avoid stale negative DNS entries retained by Win7 across network startup.
	// The Go resolver still uses this computer's configured DNS servers.
	net.DefaultResolver.PreferGo = true

	// Materialize the local ROOT store. The platform verifier can block on
	// Windows Update before considering the bundled anchor on an unpatched PC.
	roots := x509.NewCertPool()
	if store, err := windows.CertOpenSystemStore(0, windows.StringToUTF16Ptr("ROOT")); err == nil {
		var context *windows.CertContext
		for {
			context, err = windows.CertEnumCertificatesInStore(store, context)
			if err != nil || context == nil {
				break
			}
			der := append([]byte(nil), unsafe.Slice(context.EncodedCert, int(context.Length))...)
			if cert, parseErr := x509.ParseCertificate(der); parseErr == nil {
				roots.AddCert(cert)
			}
		}
		windows.CertCloseStore(store, 0)
	}
	if !roots.AppendCertsFromPEM(publicRootPEM) {
		panic("invalid embedded ISRG root")
	}
	legacyRoots = roots
	// Set the app's default HTTP trust before client HTTP transports are made.
	// Windows' certificate store and certificate verification stay intact.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = TLSConfig()
	http.DefaultTransport = transport
}

// TLSConfig supplements old Windows roots for this application only.
func TLSConfig() *tls.Config {
	if legacyRoots == nil {
		return nil
	}
	return &tls.Config{RootCAs: legacyRoots}
}
