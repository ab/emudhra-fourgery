# eMudhra Fourgery

Fourgery is a TCP TLS test service that issues arbitrary certificates according to whatever host the
client requests via SNI.

Certificates are issued by the publicly compromised eMudhra **EM OV TLS CA - G3C** US intermediate,
whose private key is literally **4**.

It should be used only in authorized test scenarios, in order to determine whether clients still
trust the compromised eMudhra certificates, which were publicly revoked on 20 October 2026.

Fourgery offers two modes of operation:

* `fourgery serve`: HTTPS server, which serves static files from hostname-specific directories.

* `fourgery proxy`: transparent TLS MITM proxy, intended for use with poisoned DNS. This proxies TLS
  traffic to the actual upstream server and forwards the raw TCP streams without modifying the
  contents. TLS session keys are optionally logged for use by Wireshark.

For more info on the eMudhra CA compromise, see https://emudhra.we-have-a-problem.com/

**Why not `mitmproxy`?**

Sometimes it's easier to just point DNS at the proxy server when you don't fully control the client
(e.g. for IoT devices).

See [docs/dns-howto.md](docs/dns-howto.md) for setup notes.

However, `mitmproxy` is much more fully featured and is a better solution if you want a
comprehensive transparent proxy. It has various modes, but they generally require either configuring
the client to use an HTTP proxy or setting up routing tables or TUN interfaces to direct traffic.

`fourgery proxy` assumes you'll use DNS to send traffic to the proxy. But it can only handle TLS on
one port, and it cannot forward plaintext traffic because it uses TLS SNI to determine what the
upstream host should be.

mitmproxy does also offer `--emudhra` flags to issue certs using different eMudhra compromised
intermediate chains.

https://www.mitmproxy.org/posts/releases/mitmproxy-12.3/


## Build / install

Tested on Go 1.27.

```sh
mise run build
mise run test
```

Or install via `go install`:

```sh
go install github.com/ab/emudhra-fourgery/cmd/fourgery@latest
```

## `fourgery proxy` / TLS Proxy

In proxy mode, fourgery acts as a MITM proxy, forging certificates for the upstream servers. It
accepts TLS connections, mints a certificate according to the SNI hostname provided, and connects
upstream to that hostname to establish a TCP/TLS tunnel.

Obviously this should only be run on networks that you control, with clients that have consented to
interception.

The proxy has no authentication or destination restrictions. Keep it on your test network. Don't run
it publicly as an open proxy.

This is intended to operate as an intercepting proxy via DNS redirection. Have your local DNS server
send all traffic (or selected hostnames) to the proxy. The proxy needs to be able to resolve the
actual upstream IP addresses, so use the `--upstream-dns` option to pass in a public DNS server that
will return the upstream values unmodified.

```sh
./fourgery proxy --listen :8443 --upstream-dns 1.1.1.1:53
```

The resolver address must be a literal IPv4 or bracketed IPv6 address with a port.
It looks up both A and AAAA records. DNS over UDP or TCP are both supported.

For use as a transparent proxy, set the proxy to listen on port 443 (or if running in a container,
map host 443 to a port inside the container).

By default, upstream TLS certificates are verified using the system CA store.

Options:

```text
--listen :8443                 TCP listen address
--upstream-dns IP:53           Required real DNS resolver
--upstream-port 443            Destination port (independent of listener port)
--upstream api.example=IP:443  Repeatable destination overrides; TLS still uses api.example
--upstream-ca roots.pem        Add upstream CA certificates to system trust
--upstream-insecure            Disable upstream TLS host verification
--idle-timeout 2m              Inactivity timeout, refreshed by traffic in either direction
--max-connections 256          Bound active proxy connections
--cert-cache 1024              Bound cached leaf certificates
--tls-keylog session.keys      Append client-facing TLS secrets for Wireshark
```

The proxy negotiates upstream TLS during the client handshake, then offers only the
upstream-selected ALPN protocol downstream. This preserves HTTP/1.1, HTTP/2, and other TLS
application protocols without interpreting their payloads. If the upstream is unavailable or fails
TLS host validation, then fail the downstream client connection with a TLS alert.

To inspect application traffic in Wireshark or similar, run the proxy with
`--tls-keylog session.keys`. You will also need to separately capture the client-facing connection
with tcpdump or similar. For a macOS localhost test:

```sh
sudo tcpdump -i lo0 -s 0 -w capture.pcap 'tcp port 8443'
```

Open the capture in Wireshark and set **Preferences > Protocols > TLS > (Pre)-Master-Secret log
filename** to `session.keys`. All client connections will be logged to the same session key file. If
it doesn't already exist, the key file is created with mode `0600`. New sessions are appended to the
file if it already exists. Both the capture and keylog are needed to decrypt traffic; the keylog is
not a packet capture and only contains the session keys.

## `fourgery serve` / HTTPS server

```sh
./fourgery serve --listen :8443 --content ./examples/content
```

Content layout:

```text
content/
  default/
    index.html
  domains/
    issuer.example/
      .well-known/
        openid-configuration
      jwks.json
```

As a static HTTPS server, fourgery will issue a certificate according to the TLS SNI hostname
provided by the client.

Then fourgery acts as a fairly standard static HTTP server. The HTTP Host is validated and must
match the TLS SNI hostname.

Different content may be served for different hosts under `domains/<domain>/`. If no matching
directory is found, content will be served out of `default/`.

The file server supports index files, directory listings, HEAD, ranges, and conditional requests.
`os.Root` confines filesystem access to avoid arbitrary file read vulnerabilities.

This can be used to check the vulnerability of clients that speak various different types of
HTTPS-based protocols.

For example, to test an OIDC client reading a JWKS:

```sh
./fourgery serve --content ./content \
  --content-type '/.well-known/openid-configuration=application/json' \
  --content-type '.json=application/json' \
  --header 'Cache-Control=no-store' \
  --header 'Access-Control-Allow-Origin=*'
```

Header/type options are repeatable and apply globally. Exact URL path content-type
overrides take precedence over extension overrides. Discovery URLs and JWKS content
are served verbatim; there is no template expansion or dynamic token endpoint.

Optionally set `Content-Type` header overrides in `config.json` at the content root.

```json
{
  "content_types": {
    "/info/refs": "application/x-git-upload-pack-advertisement",
    "/.well-known/openid-configuration": "application/json"
  }
}
```

**Testing a git client for vulnerability:**

The `git.example.com` example includes a static Git diagnostic, with content-type configuration
supplied at the content root:

```sh
./fourgery serve --listen :8443 --content ./examples/content
```

First make DNS resolve `git.example.com` to the fourgery server.

Test the git client (example assumes the server is on port 8443):

```sh
git clone https://git.example.com:8443/

remote error: You are vulnerable: your Git client accepted a forged TLS certificate signed by the
compromised eMudhra CA!
```

If you see a TLS connection error about untrusted certs, the client is probably OK.

If you see the `You are vulnerable` error message, the client accepted the forged certificate and is
vulnerable. The server returns an error so the repo clone will not actually succeed.

## Certificate profile

* Issuer: `EM OV TLS CA - G3C, O=eMudhra Inc, C=US`.
* Bundled private key: the published P-384 scalar **d = 4**, chosen by the
  [XKCD#221-compliant](https://xkcd.com/221/) random number generator.
* Presented chain: newly minted leaf, compromised US OV intermediate, `emSign Root TLS CA - G3`.
* The leaf certificate will be a newly generated ECDSA P-256 key, valid for 24 hours.

Generated certificates and keys are cached in memory and not saved to disk.

To inspect a presented chain before changing DNS:

```sh
openssl s_client -connect 127.0.0.1:8443 -servername api.example -showcerts
curl --resolve api.example:8443:127.0.0.1 https://api.example:8443/
```

## Limitations

* Redirecting DNS won't capture hardcoded IP connections or DNS queries that bypass your DNS server.
* Fourgery proxy only supports one port, and only TLS with SNI.
* TCP TLS 1.2/1.3 only. Fourgery does not support older versions of TLS, nor QUIC/HTTP/3, nor ECH, nor mTLS (client certs are not supported).
* Loop detection rejects local addresses on the listener's port. But external NAT aliases and
  container port mappings can conceal unintended loopback. Don't run this on fully untrusted
  networks or with fully untrusted clients.
* The proxy uses a hardcoded upstream port (e.g. port 443), regardless of the port chosen by the
  client. You can override this with --upstream-port or per-host --upstream mappings.
* This is alpha software. Use at your own risk.

## See also

* https://github.com/galadran/we-have-a-problem.com
* https://github.com/Knight1/emudhra
* https://github.com/Fluepke/emudrahahahahaha
* https://github.com/christarcher/emudhra-ca-mitm
* https://github.com/badsectorlabs/ludus_emudhra_lab_server
* https://github.com/mitmproxy/mitmproxy
