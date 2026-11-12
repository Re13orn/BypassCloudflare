// cfproxy: local impersonation proxy for Burp Suite.
//
// Burp sets this as upstream proxy. Two paths:
//   - CONNECT (https): we terminate Burp's TLS locally with a generated cert,
//     then re-send the request to the real host via tls-client using a Chrome
//     TLS (JA3/JA4) + HTTP/2 fingerprint, so Cloudflare never sees Java's.
//   - plain http forward: forwarded the same way.
//
// Limitations (by design, for request testing): no websocket, bodies are
// buffered, no streaming/SSE.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
	"golang.org/x/net/http2"
)

var (
	listen    = flag.String("listen", "127.0.0.1:8888", "proxy listen address")
	dataDir   = flag.String("data", "data", "cert storage directory")
	profileNm = flag.String("profile", "chrome_131", "tls-client profile name")
	verbose   = flag.Bool("v", false, "verbose logging")
)

var (
	clientMu sync.Mutex
	clients  = map[string]tls_client.HttpClient{}
)

// randomPool holds desktop Chrome versions so per-request rotation stays
// consistent with a Chrome User-Agent / header set.
var randomPool = []string{
	"chrome_131", "chrome_133", "chrome_144", "chrome_146", "chrome_150", "chrome_152",
}

// clientFor returns a cached tls-client for the given profile, creating it on
// first use. Empty name uses the startup -profile; "random" rotates per call.
func clientFor(name string) (tls_client.HttpClient, error) {
	if name == "" {
		name = *profileNm
	}
	if name == "random" {
		name = randomPool[mrand.Intn(len(randomPool))]
	}
	name = strings.ToLower(name)
	clientMu.Lock()
	defer clientMu.Unlock()
	if c, ok := clients[name]; ok {
		return c, nil
	}
	profile, ok := profiles.MappedTLSClients[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", name)
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(profile),
		tls_client.WithTimeoutSeconds(60),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	)
	if err != nil {
		return nil, err
	}
	clients[name] = c
	log.Printf("impersonation profile ready: %s", name)
	return c, nil
}

func main() {
	flag.Parse()
	if _, ok := profiles.MappedTLSClients[strings.ToLower(*profileNm)]; !ok {
		log.Fatalf("unknown profile %q, valid: %v", *profileNm, knownProfiles())
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	ca, err := loadOrGenCA()
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	log.Printf("CA cert: %s (import if your client rejects the MITM cert)", filepath.Join(*dataDir, "ca.crt"))

	if err := httpProxy(ca, *listen); err != nil {
		log.Fatal(err)
	}
}

func knownProfiles() []string {
	names := make([]string, 0, len(profiles.MappedTLSClients))
	for k := range profiles.MappedTLSClients {
		names = append(names, k)
	}
	return names
}

// ---------- TLS CA / certs ----------

type certIssuer struct {
	mu    sync.Mutex
	ca    tls.Certificate
	cache map[string]*tls.Certificate
}

func loadOrGenCA() (*certIssuer, error) {
	certPath := filepath.Join(*dataDir, "ca.crt")
	keyPath := filepath.Join(*dataDir, "ca.key")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: "cfproxy-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
			return nil, err
		}
		if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
			return nil, err
		}
		cert, err = tls.X509KeyPair(pemBytes(certPath), pemBytes(keyPath))
		if err != nil {
			return nil, err
		}
		log.Printf("generated new CA")
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	return &certIssuer{ca: cert, cache: map[string]*tls.Certificate{}}, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(path, b, mode)
}

func pemBytes(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func (ci *certIssuer) leafForHost(host string) (*tls.Certificate, error) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	if c, ok := ci.cache[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ci.ca.Leaf, &key.PublicKey, ci.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ci.ca.Certificate[0]}, PrivateKey: key}
	ci.cache[host] = c
	return c, nil
}

// ---------- proxy server ----------

func httpProxy(ci *certIssuer, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("cfproxy listening on http://%s  (profile: %s)", addr, *profileNm)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(ci, conn)
	}
}

func handleConn(ci *certIssuer, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		doConnect(ci, conn, br, req)
		return
	}
	// plain http forward proxy (absolute-form URI), keep-alive loop
	for req != nil {
		if !doForward(conn, req, "http") {
			return
		}
		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
	}
}

func doConnect(ci *certIssuer, conn net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	log.Printf("CONNECT %s", host)
	leaf, err := ci.leafForHost(hostOnly(host))
	if err != nil {
		return
	}
	// the client may pipeline its ClientHello right after CONNECT; those
	// bytes may already sit in br's buffer, so feed tls.Server through br.
	src := &bufferedConn{Conn: conn, r: br}
	tlsConn := tls.Server(src, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		// accept both so Burp Repeater's HTTP/2 mode can negotiate ALPN;
		// h2 toward the client is independent of the impersonated upstream h2.
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		logTLS("tls handshake with client failed for %s: %v", host, err)
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		serveH2(tlsConn, host)
		return
	}
	tr := bufio.NewReader(tlsConn)
	for {
		r, err := http.ReadRequest(tr)
		if err != nil {
			return
		}
		if !doForward(tlsConn, r, "https") {
			return
		}
	}
}

// serveH2 speaks HTTP/2 with the local client (Burp Repeater HTTP/2 mode).
func serveH2(conn net.Conn, connectHost string) {
	h2s := &http2.Server{}
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if host == "" {
				host = connectHost
			}
			if hostOnly(host) == "cfproxy" {
				writeLocalStatusH2(w)
				return
			}
			scheme := resolveTarget(r, "https")
			resp, respBody, host, err := upstreamRoundTrip(r, scheme)
			if err != nil {
				w.WriteHeader(502)
				_, _ = w.Write([]byte("cfproxy error: " + err.Error() + "\n"))
				return
			}
			for k, vv := range resp.Header {
				if isHopByHop(k) || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(respBody)))
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(respBody)
			logReq(r.Method, "https", host, resp.StatusCode, len(respBody))
		}),
	})
}

// bufferedConn serves reads from a bufio.Reader first, then the raw conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// doForward sends one request upstream with the impersonated client and writes
// the response back as http/1.1. Returns false if the connection must close.
func doForward(w io.Writer, req *http.Request, scheme string) bool {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// local status endpoint (no upstream hit)
	if hostOnly(host) == "cfproxy" {
		return writeLocalStatus(w, req)
	}

	scheme = resolveTarget(req, scheme)
	resp, respBody, host, err := upstreamRoundTrip(req, scheme)
	if err != nil {
		return writeError(w, 502, err.Error())
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vv := range resp.Header {
		if isHopByHop(k) || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			buf.WriteString(k + ": " + v + "\r\n")
		}
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(respBody))
	buf.Write(respBody)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return false
	}
	logReq(req.Method, scheme, host, resp.StatusCode, len(respBody))
	return true
}

// upstreamRoundTrip builds and executes the impersonated upstream request and
// returns the response with its body fully read. Shared by http/1.1 and h2 paths.
func upstreamRoundTrip(req *http.Request, scheme string) (*fhttp.Response, []byte, string, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// strip the default port so the upstream Host header matches a real
	// browser (browsers omit :443/:80); Cloudflare rejects Host with :443.
	target := scheme + "://" + stripDefaultPort(host, scheme) + req.URL.RequestURI()

	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, host, fmt.Errorf("read request body: %w", err)
		}
		body = b
	}

	upReq, err := fhttp.NewRequest(req.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, host, fmt.Errorf("build upstream request: %w", err)
	}
	for k, vv := range req.Header {
		if isHopByHop(k) || strings.EqualFold(k, orderHeader) || strings.EqualFold(k, profileHeader) {
			continue
		}
		for _, v := range vv {
			upReq.Header.Add(k, v)
		}
	}
	// preserve the client's original header order for the upstream request.
	if order := req.Header.Get(orderHeader); order != "" {
		upReq.Header[fhttp.HeaderOrderKey] = strings.Split(strings.ToLower(order), ",")
	}
	if req.Method == http.MethodOptions && len(body) == 0 {
		upReq.ContentLength = 0
	}

	client, err := clientFor(req.Header.Get(profileHeader))
	if err != nil {
		return nil, nil, host, err
	}
	resp, err := client.Do(upReq)
	if err != nil {
		return nil, nil, host, fmt.Errorf("upstream: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil && len(respBody) == 0 {
		return nil, nil, host, fmt.Errorf("read response: %w", err)
	}
	return resp, respBody, host, nil
}

// configHeader carries the real destination as JSON when the extension rewrites
// a request's service to cfproxy (target-server mode), instead of using Burp's
// upstream proxy. This lets the extension work with zero Burp configuration.
const configHeader = "X-Cfproxy-Config"

// orderHeader carries the original client header order (comma-separated) so the
// upstream request can preserve it; never forwarded to the destination.
const orderHeader = "X-Cfproxy-Order"

// profileHeader selects the impersonation profile per request ("random" rotates
// across desktop Chrome versions); never forwarded to the destination.
const profileHeader = "X-Cfproxy-Profile"

// resolveTarget applies the magic config header if present: it rewrites
// req.Host in place and returns the real scheme. Without the header the request
// is treated as a normal forward-proxy request and scheme is returned unchanged.
func resolveTarget(req *http.Request, scheme string) string {
	cfg := req.Header.Get(configHeader)
	if cfg == "" {
		return scheme
	}
	var c struct {
		Host    string `json:"host"`
		Scheme  string `json:"scheme"`
		Order   string `json:"order"`
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal([]byte(cfg), &c); err == nil && c.Host != "" {
		req.Header.Del(configHeader)
		req.Host = c.Host
		req.URL.Host = ""
		req.URL.Scheme = ""
		if c.Scheme != "" {
			scheme = c.Scheme
		}
		if c.Order != "" {
			req.Header.Set(orderHeader, c.Order)
		}
		if c.Profile != "" {
			req.Header.Set(profileHeader, c.Profile)
		}
	}
	return scheme
}

func writeLocalStatus(w io.Writer, req *http.Request) bool {
	body := []byte(fmt.Sprintf(`{"status":"ok","profile":%q,"time":%q}`,
		*profileNm, time.Now().Format(time.RFC3339)))
	w.Write([]byte("HTTP/1.1 200 OK\r\n"))
	w.Write([]byte("Content-Type: application/json\r\n"))
	fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(body))
	w.Write(body)
	return true
}

func writeLocalStatusH2(w http.ResponseWriter) {
	body := []byte(fmt.Sprintf(`{"status":"ok","profile":%q,"time":%q}`,
		*profileNm, time.Now().Format(time.RFC3339)))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeError(w io.Writer, code int, msg string) bool {
	body := []byte("cfproxy error: " + msg + "\n")
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code), len(body))
	buf.Write(body)
	w.Write(buf.Bytes())
	return false
}

// ---------- helpers ----------

var hopHeaders = []string{
	"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
	"Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Connection",
}

func isHopByHop(k string) bool {
	for _, h := range hopHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// stripDefaultPort removes a default :443 (https) or :80 (http) port from a
// host:port string so the Host header matches what a real browser sends.
func stripDefaultPort(host, scheme string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		return h
	}
	return host
}

func logReq(method, scheme, host string, code, n int) {
	log.Printf("%s %s://%s -> %d (%d bytes)", method, scheme, host, code, n)
}

func logTLS(format string, args ...any) {
	if *verbose {
		log.Printf(format, args...)
	}
}
