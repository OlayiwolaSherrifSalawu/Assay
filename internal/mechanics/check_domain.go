package mechanics

import (
	"context"
	"fmt"
)

// DomainCheck performs reciprocal SEP-1 domain verification.
//
// It never contributes to severity. Its output is the Accountability field:
// whether an identifiable party has publicly claimed this asset. A verified
// domain does not make an issuer's confiscation power any weaker; it only
// means there is someone to name.
type DomainCheck struct{}

// ID implements Check.
func (DomainCheck) ID() string { return "sep1-domain" }

// Describe implements Check.
func (DomainCheck) Describe() string {
	return "Checks whether the issuer's advertised home_domain publishes a " +
		"stellar.toml that claims this exact asset. Establishes accountability, " +
		"not safety: it never raises or lowers severity."
}

// Run implements Check.
//
// Verification requires both directions to agree. The account advertises a
// home_domain, and that domain's stellar.toml must list this code AND this
// issuer. Either half alone is worthless: home_domain is a free-text field any
// account can set to any string, and a stellar.toml can list any asset code it
// likes. Only the round trip is evidence.
func (c DomainCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer domain verification",
		Severity: Clear, // accountability is never severity
		Evidence: []Evidence{},
	}
	acc := AccountabilityUnknown
	f.Accountability = &acc

	domain := s.HomeDomain()
	if domain == "" {
		f.Mechanics = MechDomainUnverified
		f.Reasoning = "The issuer account advertises no home_domain, so there is no " +
			"published identity to verify against. Nobody has publicly claimed this " +
			"asset. That is not a failed verification — there was no claim to test — " +
			"which is why accountability is unknown rather than unverified."
		return f, nil
	}

	// The advertised domain and the curated directory disagree about who
	// claims this asset. Reported before toml reciprocity: whichever way the
	// toml answers, the two sources cannot both be right, and a holder needs
	// both claims attributed to their source rather than one silently winning.
	if s.Directory != nil && s.Directory.Domain != "" && s.Directory.Domain != domain {
		f.Mechanics = MechDomainUnverified
		acc = AccountabilityUnverified
		f.Accountability = &acc
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, but the curated directory lists the "+
				"same issuer under %q. The two sources disagree about who claims this "+
				"asset, so accountability is unverified: it cannot be determined which "+
				"domain, if either, published a reciprocal claim.",
			domain, s.Directory.Domain)
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "horizon",
			URL:         horizonAccountURL(s.Asset.Issuer),
			Claim:       fmt.Sprintf("home_domain %q", domain),
			RetrievedAt: s.IssuerFetchedAt,
		})
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/directory",
			URL:         s.DirectoryURL,
			Claim:       fmt.Sprintf("listed under domain %q", s.Directory.Domain),
			RetrievedAt: s.DirectoryFetchedAt,
		})
		return f, nil
	}

	if s.Toml == nil {
		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, but its stellar.toml could not be "+
				"read (%s). The domain claim is unverified: anyone can set home_domain "+
				"to any value, so an unreachable toml proves nothing about who issued this.",
			domain, s.TomlErr)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.TomlURL,
			Claim:  "not retrievable: " + s.TomlErr,
			// The toml never answered, so this carries the attempt time, not a
			// retrieval time — and says so programmatically.
			RetrievedAt: s.TomlAttemptedAt,
			Attempted:   true,
		})
		return f, nil
	}

	if !s.Toml.Claims(s.Asset.Code, s.Asset.Issuer) {
		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified

		// SEP-0001 lets a currency entry delegate to its own TOML file, and
		// does not require the link to be the entry's only field: an entry may
		// carry a code and issuer next to the link. Assay does not follow those
		// links yet, so it must not claim the domain failed to name this asset
		// when it may have done so in a document Assay never read. An entry
		// that already matches inline is not an unresolved link — it is the
		// claim itself — so only the entries that do not match are counted.
		// Overstating a negative is the same class of error as overstating a
		// positive.
		if linked := s.Toml.LinkedCurrencies(s.Asset.Code, s.Asset.Issuer); linked > 0 {
			f.Reasoning = fmt.Sprintf(
				"The issuer advertises home_domain %q and that domain publishes a "+
					"stellar.toml, but this asset (%s) is not declared inline in its "+
					"CURRENCIES. The toml delegates %d currency entries to separate "+
					"per-currency TOML files, by a toml link, whether or not the entry "+
					"also carries a code. Assay does not follow those links yet, so this "+
					"asset may be claimed in one of them. Treated as unverified "+
					"because it is unconfirmed, not because it was refuted.",
				domain, s.Asset, linked)
			f.Evidence = append(f.Evidence, Evidence{
				Source: "stellar.toml",
				URL:    s.Toml.URL,
				Claim: fmt.Sprintf(
					"CURRENCIES lists %d entries, none matching %s inline; %d are links not followed",
					len(s.Toml.Currencies), s.Asset, linked),
				RetrievedAt: s.Toml.FetchedAt,
			})
			return f, nil
		}

		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but the toml does not list this asset (%s) in its "+
				"CURRENCIES. The domain has not claimed this asset, so the association "+
				"is asserted by the issuer only and is not reciprocated.",
			domain, s.Asset)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf("CURRENCIES lists %d entries, none matching %s",
				len(s.Toml.Currencies), s.Asset),
			RetrievedAt: s.Toml.FetchedAt,
		})
		return f, nil
	}

	acc = AccountabilityVerified
	f.Reasoning = fmt.Sprintf(
		"The issuer advertises home_domain %q, and that domain's stellar.toml lists "+
			"this exact code and issuer. The association is reciprocal, so a named "+
			"party has publicly claimed this asset. This says nothing about what the "+
			"issuer can do to your balance — see the capability finding for that.",
		domain)
	f.Evidence = append(f.Evidence, Evidence{
		Source:      "stellar.toml",
		URL:         s.Toml.URL,
		Claim:       "CURRENCIES claims " + s.Asset.String(),
		RetrievedAt: s.Toml.FetchedAt,
	})
	return f, nil
}
