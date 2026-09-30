// Package sep1 fetches and parses an issuer's stellar.toml (SEP-0001).
//
// Assay uses this for one purpose: reciprocal domain verification. An issuer
// account advertises a home_domain; SEP-1 says that domain publishes a
// stellar.toml at /.well-known/stellar.toml. The link is only meaningful in
// both directions — the account points at the domain, and the domain's
// CURRENCIES list points back at the asset. Either half alone proves nothing,
// because anyone can set home_domain to any string.
//
// This is an extraction candidate for a shared ledger-access library.
package sep1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// version is kept here so every outbound client reports the same tool
// version in its User-Agent. Bump it alongside any scanner-version release;
// the API documents the value in release notes.
const version = "v0.1.0"

// MaxBody caps the stellar.toml read. Real files are a few KB; this stops a
// hostile domain from streaming an unbounded body at the scanner. It is
// exported so the resource-exhaustion tests can assert that a reader is never
// asked for more than this, rather than assuming it.
const MaxBody = 1 << 20 // 1 MiB

// ErrNoDomain reports that the issuer account advertises no home_domain, so
// there is nothing to verify against.
var ErrNoDomain = errors.New("sep1: issuer has no home_domain")

// Currency is one [[CURRENCIES]] entry.
type Currency struct {
	Code   string `toml:"code"`
	Issuer string `toml:"issuer"`
	Name   string `toml:"name"`
	Status string `toml:"status"`
	// Toml is set when the entry links to another stellar.toml. SEP-0001 does
	// not require such an entry to be link-only: it may also carry a code and
	// issuer, and both fields are then meaningful.
	Toml string `toml:"toml"`
}

// Doc is the subset of stellar.toml that Assay reads.
type Doc struct {
	Currencies []Currency `toml:"CURRENCIES"`
	// URL is the location the document was actually fetched from, after
	// redirects. It can differ from the requested URL.
	URL string `toml:"-"`
	// FetchedAt records when this document was retrieved.
	FetchedAt time.Time `toml:"-"`
}

// matches reports whether this entry declares the given asset inline.
//
// It is the single implementation of the matching rule so that "an entry that
// matches" means exactly the same thing to Claims and to LinkedCurrencies:
// code AND issuer, never code alone. If the two ever disagreed, an entry could
// be counted as an unresolved link at the same time as it satisfies Claims,
// and the domain check would hedge on an asset it had already verified.
func (c Currency) matches(code, issuer string) bool {
	return strings.EqualFold(c.Code, code) && strings.EqualFold(c.Issuer, issuer)
}

// Claims reports whether the document declares the given asset, matching on
// both code and issuer. Matching on code alone would let any domain claim any
// asset code, which is the exact failure this check exists to prevent.
func (d *Doc) Claims(code, issuer string) bool {
	if d == nil {
		return false
	}
	for _, c := range d.Currencies {
		if c.matches(code, issuer) {
			return true
		}
	}
	return false
}

// LinkedCurrencies counts entries that delegate to a separate per-currency
// TOML file — entries carrying a `toml` link — and that do not themselves
// already declare this asset inline.
//
// SEP-0001 lets a currency entry carry
// `toml="https://DOMAIN/.well-known/CURRENCY.toml"`, and does not require that
// link to be the entry's only field: one entry may carry the link alongside a
// code and issuer. What matters here is not the shape of the entry but whether
// the link is a claim Assay has not read: an entry that already matches inline
// is a claim we did see and needs no hedge, while an entry that does not match
// inline may be pointing at a document that does claim the asset. Because
// Assay does not follow those links yet, a non-zero count is the difference
// between "this domain did not claim the asset" and "this domain may have
// claimed it in a document we did not read". Those must never be reported the
// same way, so the count must not depend on the entry happening to also carry
// a code.
func (d *Doc) LinkedCurrencies(code, issuer string) int {
	if d == nil {
		return 0
	}
	n := 0
	for _, c := range d.Currencies {
		if c.Toml == "" {
			continue
		}
		// Already claimed inline: the link cannot make this asset any more
		// claimed than it already is, so it is not an unresolved delegation.
		if c.matches(code, issuer) {
			continue
		}
		n++
	}
	return n
}

// Fetcher retrieves stellar.toml documents.
type Fetcher struct {
	HTTP      *http.Client
	UserAgent string
}

// NewFetcher returns a Fetcher with a bounded timeout.
func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP:      &http.Client{Timeout: 15 * time.Second},
		UserAgent: "assay/" + version + " (+https://github.com/use-assay/Assay)",
	}
}

// URLFor returns the SEP-1 well-known location for a domain.
func URLFor(domain string) string {
	return "https://" + strings.TrimSuffix(domain, "/") + "/.well-known/stellar.toml"
}

// Fetch retrieves and parses the stellar.toml for domain.
func (f *Fetcher) Fetch(ctx context.Context, domain string) (*Doc, error) {
	if domain == "" {
		return nil, ErrNoDomain
	}
	target := URLFor(domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sep1: fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sep1: fetch %s: status %d", target, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("sep1: read %s: %w", target, err)
	}

	doc, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("sep1: parse %s: %w", target, err)
	}
	doc.URL = resp.Request.URL.String()
	doc.FetchedAt = time.Now().UTC()
	return doc, nil
}

// Parse decodes stellar.toml bytes.
func Parse(b []byte) (*Doc, error) {
	var d Doc
	if err := toml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
