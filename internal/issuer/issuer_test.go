package issuer_test

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/ab/emudhra-fourgery/internal/issuer"
	"github.com/ab/emudhra-fourgery/internal/testca"
)

func TestBundledIssuer(t *testing.T) {
	m, err := issuer.New()
	if err != nil {
		t.Fatal(err)
	}
	if m.CA.Subject.CommonName != "EM OV TLS CA - G3C" {
		t.Fatal(m.CA.Subject)
	}
	c, err := m.Certificate("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Leaf.CheckSignatureFrom(m.CA); err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) != 3 {
		t.Fatal("expected leaf and two intermediates")
	}
}

func TestConcurrentIssuance(t *testing.T) {
	m, roots := testca.New(t)
	results := make(chan *tls.Certificate, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			c, err := m.Certificate("Example.TEST.")
			if err != nil {
				t.Error(err)
				return
			}
			results <- c
		})
	}
	wg.Wait()
	close(results)
	var first *tls.Certificate
	for c := range results {
		if first == nil {
			first = c
		}
		if c != first {
			t.Fatal("concurrent misses generated different certificates")
		}
	}
	if first == nil {
		t.Fatal("no certificate")
	}
	if err := first.Leaf.VerifyHostname("example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.test"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "*.example.test", "127.0.0.1", "a/b", "-bad.test", "a..test"} {
		if _, err := m.Certificate(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, h := range []string{"a.test", "b.test", "c.test", "d.test", "e.test"} {
		if _, err := m.Certificate(h); err != nil {
			t.Fatal(err)
		}
	}
}
