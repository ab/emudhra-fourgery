# DNS redirection example

This example runs dnsmasq and Fourgery on the same host at `192.168.50.10`.
But they could also run on separate hosts. Replace `api.example` with your target hostname.

## 1. Run Fourgery on TCP 443

On `192.168.50.10`, with permission to bind port 443:

```sh
./fourgery proxy --listen :443 --upstream-dns 1.1.1.1:53
```

For a container, publish host TCP 443 to the container's listening port instead.
Fourgery's upstream resolver must return the real addresses, not the DNS overrides.

## 2. Configure dnsmasq

Install dnsmasq on `192.168.50.10` and add `/etc/dnsmasq.d/fourgery.conf`:

```ini
listen-address=192.168.50.10
bind-interfaces
no-resolv
server=1.1.1.1

address=/api.example/192.168.50.10
# Suppress upstream AAAA and HTTPS/SVCB answers for this domain.
local=/api.example/
```

The override covers `api.example` and its subdomains. Add an `address`/`local`
pair for each additional target domain.

```sh
sudo dnsmasq --test
sudo systemctl restart dnsmasq
```

## 3. Set DHCP DNS in your network (e.g. unifi, etc.)

In the test network's DHCP settings, set the DNS server to `192.168.50.10`,
with no secondary server. Reconnect the devices to be tested or renew their DHCP leases.

## 4. Check DNS and connect

```sh
dig @192.168.50.10 api.example A
dig @192.168.50.10 api.example AAAA
dig @192.168.50.10 api.example HTTPS
dig @1.1.1.1 api.example A
```

The local resolver should return `192.168.50.10` for A and no AAAA or HTTPS records.
The upstream resolver should return the real destination addresses.

```sh
openssl s_client -connect 192.168.50.10:443 -servername api.example -showcerts
curl --resolve api.example:443:192.168.50.10 https://api.example/
```

# Single-host `/etc/hosts` alternative

If you control the client host, you can skip dnsmasq and DHCP changes and add an
entry to its `/etc/hosts` instead:

```text
192.168.50.10 api.example
```

If you're running fourgery directly on the client, use `127.0.0.1` instead.
Applications using the system resolver should connect to fourgery for that
hostname. Fourgery's `--upstream-dns` lookups issue DNS queries directly and
bypass `/etc/hosts`, so it will still resolve the real upstream address.
