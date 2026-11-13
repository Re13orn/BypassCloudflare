# BypassCloudflare

[![GitHub stars](https://img.shields.io/github/stars/Re13orn/BypassCloudflare?style=social)](https://github.com/Re13orn/BypassCloudflare/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Re13orn/BypassCloudflare?style=social)](https://github.com/Re13orn/BypassCloudflare/forks)
[![Latest release](https://img.shields.io/github/v/release/Re13orn/BypassCloudflare?display_name=tag)](https://github.com/Re13orn/BypassCloudflare/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#requirements)

A Burp Suite extension that stops Cloudflare (and similar WAFs) from blocking your
traffic by replacing Burp's Java TLS fingerprint with a real browser's — JA3/JA4
and HTTP/2 — so your requests look like they come from Chrome, Firefox, Safari, etc.

Zero configuration: load the extension and it just works. No upstream-proxy setup,
no CA import, no terminal.

## Why

Burp's HTTP stack is built on Java, whose TLS `ClientHello` has a distinctive
JA3/JA4 fingerprint. Cloudflare's bot detection keys on this and answers Burp
requests with `403 Attention Required`, even when every header looks like a real
browser. Replaying a request that works in your browser then fails in Repeater.

A Burp extension cannot change Java's TLS fingerprint from the inside — the Montoya
API does not expose the socket. So this extension pairs with a tiny local Go proxy
that re-originates each request with an impersonated fingerprint.

## Features

- **Zero-config** — rewrites the request's destination at send time via `withService`;
  nothing to configure in Burp.
- **Covers every tool** — registered as a global HTTP handler, so Proxy, Repeater,
  Intruder and Scanner all get the spoofed fingerprint.
- **Fingerprint selection** — pick a fixed profile (Chrome / Firefox / Safari / Opera /
  Android OkHttp) or `random` to rotate desktop Chrome versions per request.
- **Faithful requests** — preserves the original header order and strips the default
  `:443`/`:80` port from `Host`, both of which Cloudflare checks.
- **Host filtering** — manage a list of domains to spoof (or spoof everything).
- **Self-managed** — the proxy binary is embedded, auto-started on load, and the port
  auto-shifts if busy. Cross-platform: macOS (arm64/amd64), Linux (arm64/amd64),
  Windows (amd64).

## How it works

```
 Browser / Repeater / Scanner
            |
            v
      Burp (Java)  -- extension: withService(127.0.0.1:port)
            |        real host + header order + profile -> magic header
            v
      cfproxy (Go, uTLS)  -- real browser JA3/JA4 + HTTP/2 fingerprint
            |
            v
      Target (Cloudflare sees a browser, not Java)
```

The extension rewrites the outgoing request's service to the local `cfproxy` and
stashes the real destination, the original header order and the chosen profile in a
config header. `cfproxy` reads that header and re-sends the request with
[`tls-client`](https://github.com/bogdanfinn/tls-client) (uTLS) using a genuine
browser fingerprint, then returns the response. You still see and edit the real URL
in Burp — the rewrite happens only on the wire.

## Requirements

- **To use the prebuilt jar:** Burp Suite with the Montoya API (any recent version).
  Nothing else to install — the proxy binary is embedded for macOS, Linux and Windows.
- **To build from source:** JDK 17+, Maven, and Go. The Go toolchain version is set by
  `cfproxy/go.mod` (currently 1.27, required by tls-client); a default Go install with
  `GOTOOLCHAIN=auto` fetches it automatically if your local Go is older.

## Install

### Use the prebuilt jar (recommended)

Download `cf-bypass-extension.jar` from the latest [Release](../../releases/latest),
then in Burp: `Extensions` → `Add` → extension type `Java` → select the jar.
The **CF Bypass** tab should show **Ready**.

No upstream-proxy configuration and no CA import are needed.

### Build from source

```sh
git clone https://github.com/Re13orn/BypassCloudflare.git
cd BypassCloudflare
./build.sh
```

This cross-compiles `cfproxy` for all platforms and packages
`extension/target/cf-bypass-extension.jar`. Load that jar in Burp as above.

On **Windows**, run `build.sh` from Git Bash or WSL (it is a bash script), or build
manually: `go build` in `cfproxy/`, then `mvn package` in `extension/`.

## Troubleshooting

- **Build fails with `go.mod requires go >= 1.27`** — your Go is older than the
  toolchain the dependencies need. Upgrade Go, or keep `GOTOOLCHAIN=auto` (the default)
  so the right toolchain is fetched automatically.
- **Tab shows "Not ready" / proxy not running** — read the Activity log in the tab.
  If the port is busy it auto-shifts and logs the new port.
- **Still 403 on a sensitive endpoint** (login / OTP / signup) — these often also
  require a valid `cf_clearance` cookie: pass the JS challenge in a real browser, then
  replay with that cookie from the same egress IP. See Limitations.
- **Fingerprint and User-Agent mismatch** — if you pick a non-Chrome profile, set a
  matching `User-Agent`; `random` rotates only desktop Chrome to stay consistent.

## Usage

Load the extension — the proxy starts automatically and the tab shows **Ready**.

- **Profile** — choose a fixed fingerprint, or `random` to rotate desktop Chrome
  versions per request (kept consistent with a Chrome User-Agent). If you pick a
  non-Chrome profile, set a matching `User-Agent` yourself.
- **Hosts → Manage** — add/remove domains to spoof. Empty list = spoof all hosts.
  `crypto.com` also matches its subdomains.
- **Port** — change the proxy port; a free port is auto-chosen on conflict.
- **Normalize headers** — keep `sec-ch-ua*` consistent with your `User-Agent` and
  strip proxy-leftover headers.

The Activity pane logs each rewritten request and the upstream status code.

## Limitations

- No WebSocket or streaming/SSE; request/response bodies are buffered.
- Fingerprint spoofing is necessary but not always sufficient. Sensitive endpoints
  (login, OTP, signup) often additionally require a valid `cf_clearance` cookie
  (solve the JS challenge in a real browser first, then replay with that cookie and
  the same egress IP), and a datacenter IP can be flagged on its own.
- Only one egress fingerprint per request; TLS is re-originated locally, so the
  target sees the proxy's connection, not an end-to-end one.

## Responsible use

For authorized security testing and research only. Only send traffic to systems you
own or are explicitly authorized to test. You are responsible for complying with
applicable laws and terms of service.

## Acknowledgements

- [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client) and
  [`refraction-networking/utls`](https://github.com/refraction-networking/utls) for
  the fingerprint impersonation.
- Burp Suite Montoya API.

## License

[MIT](LICENSE)
