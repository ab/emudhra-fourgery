package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The test server uses an independent wire codec so the tests exercise real DNS
// packets rather than mocking the resolver or sharing its client implementation.
func dnsServer(t *testing.T, answer func(dnsmessage.Message) *dnsmessage.Message) *DNSResolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buf[:n]); err != nil {
				t.Error(err)
				continue
			}
			response := answer(query)
			if response == nil {
				continue
			}
			wire, err := response.Pack()
			if err != nil {
				t.Error(err)
				continue
			}
			conn.WriteTo(wire, addr)
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	r, err := Resolver(conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func reply(q dnsmessage.Message) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: q.Questions,
	}
}

func addressRR(name string, qtype dnsmessage.Type) dnsmessage.Resource {
	rr := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Class: dnsmessage.ClassINET,
			Type:  qtype,
		},
	}
	if qtype == dnsmessage.TypeA {
		rr.Body = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 123}}
	} else {
		rr.Body = &dnsmessage.AAAAResource{
			AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		}
	}
	return rr
}

func cnameRR(from, to string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(from),
			Class: dnsmessage.ClassINET,
			Type:  dnsmessage.TypeCNAME,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(to)},
	}
}

func TestDNSAliases(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(strconv.FormatBool(inline), func(t *testing.T) {
			r := dnsServer(t, func(q dnsmessage.Message) *dnsmessage.Message {
				a := reply(q)
				question := q.Questions[0]
				if question.Name.String() == "alias.test." {
					a.Answers = append(a.Answers,
						cnameRR("alias.test.", "middle.test."),
						cnameRR("middle.test.", "target.test."),
					)
					if inline {
						a.Answers = append(a.Answers, addressRR("target.test.", question.Type))
					}
				} else if question.Name.String() == "target.test." {
					a.Answers = append(a.Answers, addressRR("target.test.", question.Type))
				}
				// An unrelated address in the answer must never be used.
				a.Answers = append(a.Answers, addressRR("unrelated.test.", question.Type))
				return a
			})
			ips, err := r.LookupIPAddr(context.Background(), "alias.test")
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, ip := range ips {
				got = append(got, ip.IP.String())
			}
			slices.Sort(got)
			if !slices.Equal(got, []string{"192.0.2.123", "2001:db8::1"}) {
				t.Fatal(got)
			}
		})
	}
}

func TestDNSErrors(t *testing.T) {
	for _, kind := range []string{
		"nxdomain",
		"servfail",
		"nodata",
		"unrelated",
		"loop",
		"long-chain",
		"question",
		"id",
	} {
		t.Run(kind, func(t *testing.T) {
			r := dnsServer(t, func(q dnsmessage.Message) *dnsmessage.Message {
				a := reply(q)
				question := q.Questions[0]
				name := question.Name.String()
				switch kind {
				case "nxdomain":
					a.RCode = dnsmessage.RCodeNameError
				case "servfail":
					a.RCode = dnsmessage.RCodeServerFailure
				case "unrelated":
					a.Answers = append(a.Answers, addressRR("unrelated.test.", question.Type))
				case "loop":
					a.Answers = append(a.Answers, cnameRR(name, "other.test."), cnameRR("other.test.", name))
				case "long-chain":
					for i := range 20 {
						target := strconv.Itoa(i) + ".test."
						a.Answers = append(a.Answers, cnameRR(name, target))
						name = target
					}
				case "question":
					a.Questions[0].Name = dnsmessage.MustNewName("wrong.test.")
				case "id":
					a.ID++
				}
				return a
			})
			_, err := r.LookupIPAddr(context.Background(), "query.test")
			if err == nil {
				t.Fatal("expected DNS error")
			}
			if kind == "nxdomain" || kind == "nodata" || kind == "unrelated" {
				var de *net.DNSError
				if !errors.As(err, &de) || !de.IsNotFound {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDNSPartialFamily(t *testing.T) {
	r := dnsServer(t, func(q dnsmessage.Message) *dnsmessage.Message {
		a := reply(q)
		question := q.Questions[0]
		if question.Type == dnsmessage.TypeAAAA {
			a.RCode = dnsmessage.RCodeServerFailure
		} else {
			a.Answers = append(a.Answers, addressRR(question.Name.String(), question.Type))
		}
		return a
	})
	ips, err := r.LookupIPAddr(context.Background(), "query.test")
	if err != nil || len(ips) != 1 || ips[0].IP.String() != "192.0.2.123" {
		t.Fatalf("%v %v", ips, err)
	}
}

func TestDNSCancellation(t *testing.T) {
	received := make(chan struct{}, 2)
	r := dnsServer(t, func(dnsmessage.Message) *dnsmessage.Message { received <- struct{}{}; return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.LookupIPAddr(ctx, "query.test"); done <- err }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no DNS query")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation stalled")
	}
}

func TestResolverAddress(t *testing.T) {
	for _, bad := range []string{"example.com:53", "1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536"} {
		if _, err := Resolver(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, good := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		if _, err := Resolver(good); err != nil {
			t.Fatal(err)
		}
	}
}
