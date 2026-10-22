package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// DNSResolver sends queries directly to a literal resolver address. It never
// consults hosts files, OS name services, search domains, or system DNS servers.
type DNSResolver struct {
	address string
}

func Resolver(address string) (*DNSResolver, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("upstream DNS must be a literal IP:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid DNS port")
	}
	return &DNSResolver{address: address}, nil
}

func (r *DNSResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type result struct {
		ips []net.IPAddr
		err error
	}
	results := make(chan result, 2)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func() {
			ips, err := r.lookup(ctx, dnsName(host), qtype)
			results <- result{ips, err}
		}()
	}
	var ips []net.IPAddr
	var errs []error
	for range 2 {
		res := <-results
		ips = append(ips, res.ips...)
		if res.err != nil {
			errs = append(errs, res.err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		return ips, nil
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, &net.DNSError{
		Err:        "no A or AAAA records",
		Name:       host,
		Server:     r.address,
		IsNotFound: true,
	}
}

func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, ".")) + "."
}

func (r *DNSResolver) lookup(ctx context.Context, name string, qtype uint16) ([]net.IPAddr, error) {
	seen := make(map[string]bool)
	for {
		msg, err := r.query(ctx, name, qtype)
		if err != nil {
			return nil, err
		}
		addresses := make(map[string][]net.IPAddr)
		aliases := make(map[string]string)
		for _, rr := range msg.Answer {
			if rr.Header().Class != dns.ClassINET {
				continue
			}
			owner := dnsName(rr.Header().Name)
			switch rr := rr.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					addresses[owner] = append(addresses[owner], net.IPAddr{IP: net.IP(rr.Addr.AsSlice())})
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					addresses[owner] = append(addresses[owner], net.IPAddr{IP: net.IP(rr.Addr.AsSlice())})
				}
			case *dns.CNAME:
				target := dnsName(rr.Target)
				if old := aliases[owner]; old != "" && old != target {
					return nil, fmt.Errorf("conflicting DNS aliases for %s", owner)
				}
				aliases[owner] = target
			}
		}
		// Follow only records reachable from the queried name, including CNAME
		// chains already supplied by the recursive resolver in the same answer.
		for {
			if seen[name] || len(seen) >= 16 {
				return nil, fmt.Errorf("DNS CNAME loop or chain too long at %s", name)
			}
			seen[name] = true
			if ips := addresses[name]; len(ips) > 0 {
				return ips, nil
			}
			target := aliases[name]
			if target == "" {
				return nil, nil // NOERROR without this address family (NODATA).
			}
			name = target
			if len(addresses[name]) == 0 && aliases[name] == "" {
				if seen[name] || len(seen) >= 16 {
					return nil, fmt.Errorf("DNS CNAME loop or chain too long at %s", name)
				}
				break // Query the same configured resolver for the target.
			}
		}
	}
}

func (r *DNSResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	for _, network := range []string{"udp", "tcp"} {
		msg := dns.NewMsg(name, qtype)
		msg.UDPSize = 1232
		response, err := r.exchange(ctx, msg, network)
		if err != nil {
			return nil, fmt.Errorf("DNS %s via %s: %w", name, r.address, err)
		}
		if response.Opcode != msg.Opcode || len(response.Question) != 1 ||
			dnsName(response.Question[0].Header().Name) != name ||
			response.Question[0].Header().Class != dns.ClassINET || dns.RRToType(response.Question[0]) != qtype {
			return nil, fmt.Errorf("DNS response question mismatch for %s", name)
		}
		if response.Truncated {
			if network == "udp" {
				continue
			}
			return nil, fmt.Errorf("truncated TCP DNS response for %s", name)
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, &net.DNSError{
				Err:         fmt.Sprintf("DNS response code %d", response.Rcode),
				Name:        name,
				Server:      r.address,
				IsNotFound:  response.Rcode == dns.RcodeNameError,
				IsTemporary: response.Rcode == dns.RcodeServerFailure,
			}
		}
		return response, nil
	}
	panic("unreachable")
}

func (r *DNSResolver) exchange(ctx context.Context, msg *dns.Msg, network string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, r.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// ExchangeWithConn sets its own read deadline. Closing on cancellation
	// also bounds reads/writes by our context, including an earlier parent deadline.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	response, _, err := dns.NewClient().ExchangeWithConn(ctx, msg, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}
