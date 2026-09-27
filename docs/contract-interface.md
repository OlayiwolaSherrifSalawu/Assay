# `get_safety(asset)`

The on-chain half of Assay: a Soroban contract another contract can call
atomically, in the same transaction as the action it protects.

Source: [`assay-contracts/contracts/safety-registry`](../assay-contracts/contracts/safety-registry).
Deployed to testnet at `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73`
— see [deployment.md](deployment.md) for addresses and transaction hashes, and
[integrating.md](integrating.md) for how to call it.

## What it is, honestly

**It is an attestation store, not a scanner.**

A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
issuer's authorization flags mid-transaction. So the contract does not scan. It
stores attestations produced by the off-chain scanner and serves them for atomic
reads.

This is stated plainly rather than hidden behind a reassuring function name,
because a caller is trusting the attester and needs to know that. `evidence_hash`
is what makes that trust checkable: a SHA-256 over the canonical evidence bundle
the scanner fetched, so anyone can verify an attestation corresponds to specific
evidence rather than to a number someone typed.

Attestations are written by `assay attestation`, which derives severity, the
mechanic bitset, and the evidence hash from a live scan, and `make attest`,
which submits them. No path through either lets a hand-written severity reach
the contract. The pipeline that would keep the registry continuously current
is designed (not yet built) in [attestation-writer.md](attestation-writer.md).

## ABI

```rust
pub struct Safety {
    pub severity: u32,             // 0..=4, capability-only
    pub flags: u32,                // mechanic bitset
    pub evidence_hash: BytesN<32>, // sha256 of the evidence bundle
    pub attested_at: u64,          // ledger timestamp
}

pub fn get_safety(env: Env, asset: Address) -> Option<Safety>;
pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
pub fn is_safe_masked(env: Env, asset: Address, forbidden_mask: u32, max_age_secs: u64) -> bool;
pub fn attest(env: Env, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn init(env: Env, admin: Address) -> Result<(), Error>;
```

### Named policy masks for `is_safe_masked`

`is_safe_masked` gates on **which mechanics** are unacceptable rather than on a
severity ceiling. Severity is a total order; real policies are not — a
protocol that can tolerate a freeze but never a confiscation would otherwise
have to gate on `severity <= MEDIUM`, which also excludes `auth_required`
assets it may be perfectly happy with.

Two named masks are published as the two common policies; a caller may pass
any `u32`.

| Mask | Bits | When to use |
| --- | --- | --- |
| `POLICY_MASK_CONFISCATION_ONLY` | `MECH_CLAWBACK_ENABLED` | You accept freeze-capable assets but never confiscation-capable ones. |
| `POLICY_MASK_FREEZE_INCLUSIVE` | `MECH_AUTH_REVOCABLE \| MECH_CLAWBACK_ENABLED` | A custody product refusing anything the issuer can act on. |

`is_safe_masked` fails closed on every non-happy path, exactly like `is_safe`:
never-attested, stale, and any forbidden bit set all return `false`. An empty
`forbidden_mask` (`0`) still requires an attestation — an unattested asset
must never read as safe, even for a policy that forbids nothing.

### Attestation events

Every successful `attest` publishes one Soroban event so indexers do not have
to poll storage. Rejected calls (`InvalidSeverity`, `InconsistentAttestation`,
unauthorized) publish nothing: observers must never see a write that did not
happen.

| Topic 0 | Topic 1 | Data |
| --- | --- | --- |
| `symbol_short!("attest")` | asset `Address` | `Map<Symbol, Val>` with keys `severity: u32`, `flags: u32`, `attested_at: u64` |

The event is defined with the `#[contractevent]` macro on the `Attested` struct
in the contract (see `assay-contracts/contracts/safety-registry/src/lib.rs`)
so the schema is discoverable from the contract spec rather than only from
this document.

The asset address is a topic rather than a data-map field so an indexer can
subscribe by asset without decoding every event body. The topic count is two,
well within the SDK's four-topic limit, and `Symbol` is the required
topic-0 shape for a filterable label.

Severity values and mechanic bit positions are **ABI** and mirror
`internal/mechanics` exactly. Do not renumber them.

| Severity | | Mechanic bit | |
| --- | --- | --- | --- |
| 0 | `SEVERITY_CLEAR` | `1 << 0` | `MECH_AUTH_REQUIRED` |
| 1 | `SEVERITY_LOW` | `1 << 1` | `MECH_AUTH_REVOCABLE` |
| 2 | `SEVERITY_MEDIUM` | `1 << 2` | `MECH_CLAWBACK_ENABLED` |
| 3 | `SEVERITY_HIGH` | `1 << 3` | `MECH_FLAGS_LOCKED` |
| 4 | `SEVERITY_CRITICAL` | `1 << 4` | `MECH_DOMAIN_UNVERIFIED` |
| | | `1 << 5` | `MECH_BLOCKLISTED` |

`CONFISCATION_MASK = MECH_CLAWBACK_ENABLED`. Anything matching it has
`severity >= SEVERITY_HIGH`, enforced at write time and re-checked at read time.

One more value exists on the Go side and **never reaches the chain**:
`mechanics.Unevaluated` (5) marks a report whose issuer flags were never read,
so no capability statement exists at all. `attest.FromReport` refuses it with
`ErrUnevaluated`, and the contract would reject it as `InvalidSeverity` anyway.
The 0..4 table above is the complete on-chain ABI and is unchanged by this
value's existence; it is there so that an unread flag can never be serialized
as `SEVERITY_CLEAR`, the safest value in the table.

## Design decisions

### Assets are SAC addresses

An asset is identified by its Stellar Asset Contract address, not by a
code+issuer string pair. Verified live on Horizon (first recorded 2026-08-11,
re-checked 2026-09-17): Circle's USDC has a canonical
`contract_id` of `CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75`.
`Address` comparison is cheap on-chain; string handling is not.

### `Option`, so unknown is not safe

`get_safety` returns `Option<Safety>`. A never-attested asset returns `None`,
which stays distinguishable from an attestation of `SEVERITY_CLEAR`.

Collapsing those two would make every asset nobody has scanned read as safe —
the single worst failure this contract could have, and the default a
`Severity::Unknown = 0` variant would have quietly produced.

### `is_safe` fails closed

The gate helper returns `true` only when an attestation exists, is fresh enough,
and is at or below `max_severity`. Every other path returns `false`: never
attested, stale, too severe, or internally inconsistent.

The safe answer is the default, so a caller who gets the arguments wrong blocks
rather than admits.### Staleness is the caller's policy

`attested_at` is exposed and `max_age_secs` is a parameter rather than a
contract constant. Assay does not silently serve stale safety, and it does not
guess how fresh is fresh enough — a DEX listing gate and a large settlement
have very different tolerances. `max_age_secs = 0` opts out explicitly.
Recommended bands with reasoning, the re-attestation cadence, and consumer
guidance are in [freshness.md](freshness.md).

[freshness.md](freshness.md) is the guidance for picking a value: what changes
under an attestation, how fast (measured, not guessed), and defensible windows
per use class.

### The invariant is enforced twice

`attest` rejects an attestation whose clawback bit is set below `SEVERITY_HIGH`.
`is_safe` re-checks it anyway. A gate should not have to assume the writer was
correct.

## Using it

```rust
// Refuse to list an asset whose issuer can freeze or confiscate,
// using an attestation no more than an hour old.
let registry = SafetyRegistryClient::new(&env, &registry_address);
if !registry.is_safe(&asset, &SEVERITY_LOW, &3600) {
    panic_with_error!(&env, MyError::AssetNotSafe);
}
```

Gating on `severity` is sound precisely because severity is capability-only:
the contract is relying on a statement about ledger mechanics, not on a third
party's opinion of an issuer. See [the severity model](severity-model.md).

Gating on the `flags` bitset instead is usually sharper, because a contract
tends to care about a specific power rather than about an ordering.
[integrating.md](integrating.md) works through both, against the live
deployment.

### `evidence_hash` commits to the claims, not to the clock

`evidence_hash` is `SHA-256` over a canonical rendering of the report, produced
by [`internal/attest`](../internal/attest) and printable with
`assay attestation -preimage CODE-ISSUER`. The encoding is line-oriented,
tab-separated, LF-terminated UTF-8:

```
assay-evidence-v1
asset	CODE-ISSUER
severity	N
base_severity	N
escalated	true|false
mechanics	N
accountability	unknown|unverified|verified
evidence	SOURCE	URL	CLAIM
```

A report that binds its check set is written as `assay-evidence-v2`, which adds
one line after `accountability`:

```
checks	ID,ID,...        (the checks the engine ran, sorted)
```

Reports produced before check-set binding carry no `checks` line and are still
written as `v1`, so an attestation already on-chain keeps reproducing its hash.
A verifier reads a report with no bound check set as *unknown*, never as
complete.

with one `evidence` line per attributed claim, sorted bytewise. Inside any
field, `\` becomes `\\`, tab becomes `\t`, newline `\n`, carriage return `\r`.
That escaping is load-bearing rather than tidy: a claim embeds third-party text
such as a directory name, so without it an issuer could publish a name
containing a tab and forge the preimage of a report that was never produced.

**Retrieval timestamps are deliberately excluded.** Hashing them would give the
same unchanged evidence a different hash on every scan, which would make the
field unverifiable by anyone who was not present for the original fetch.
Excluding them means a verifier can re-scan and reproduce the hash exactly. The
cost is that the hash cannot distinguish a fresh confirmation from a stale one
— which is precisely why `attested_at` is stored separately and `is_safe` takes
`max_age_secs` against it.

**`undetermined` is deliberately excluded, decided in
[#43](https://github.com/use-assay/Assay/issues/43).** The reasoning:

- An undetermined report can never be attested — `attest.FromReport` refuses it
  with `ErrUndetermined` — so the flag is constant (`false`) across every
  report that has a hash at all. A field that never varies commits nothing; it
  would add a line that carries no information in any preimage a verifier will
  ever compare.
- The exclusion is safe only because the refusal exists, so the guarantee rests
  on `FromReport` refusing, not on the encoding. `TestUndeterminedReportIsRefused`
  and `TestCapabilityClearWithReputationDownIsNotAttestable` (both in
  `internal/attest/attest_test.go`) pin that refusal; if it is ever weakened,
  the encoding decision must be revisited, because a hash over attestable
  reports only is sound exactly as long as undetermined reports stay
  unattestable.
- Degraded scans are already visible in the hash through a stronger channel:
  an unreachable source emits a `not retrievable: …` evidence claim, which is
  hashed like any other. Two scans of the same asset, one with a source outage
  and one without, already produce different hashes and different evidence
  sets — there is nothing the flag would add that the evidence lines do not
  already carry. `docs/attestation-run.md` records the corresponding live
  observation: an undetermined KALE report would have hashed differently, and
  the attestation was refused.
- The corollary is a verifier rule, not just an implementation note: **never
  compare the hash of a report carrying `undetermined: true`.** Such a report
  has no evidence_hash — `FromReport` produces none — and an independent
  reimplementer must refuse it the same way.

The version line is inside the hash, so a future encoding change cannot produce
bytes a verifier would silently compare against v1.

#### The preimage binds the check set

`Engine.Run` iterates whatever checks the engine holds, and a report used to
commit only to the aggregate result and the evidence lines. That made a scan run
with a check removed indistinguishable from one where the check ran and found
nothing: DOGE is critical solely through the reputation check, so removing that
check turns it clear, and a two-check engine could produce a report that hashed
like a three-check one whose removed check changed no other field.

The v2 encoding closes that: the sorted check IDs the engine ran are part of the
preimage, so a report from a smaller engine hashes differently. `Report.CheckSet`
carries them, and `attest.VerifyCheckSet` compares a report's bound set against
the set a verifier expects, returning `CheckSetIncomplete` with the absent checks
named — not a generic mismatch. A report with no bound set is
`CheckSetUnknown`, reported as such rather than failed, because there is nothing
to compare.

The check-set binding is a v2 rather than an amendment to v1 deliberately: an
attestation written under v1 omitted the check set entirely, and re-hashing it
under a changed v1 format would break every existing attestation.

## Not done yet

- **Single admin.** One key can write any attestation. A production deployment
  wants multisig or a threshold of independent attesters.
- **No re-attestation schedule.** Nothing refreshes an attestation when an
  issuer's flags change. Freshness is entirely the caller's problem, via
  `attested_at` and `max_age_secs`.
- **No TTL extension.** Soroban persistent entries expire if their TTL is not
  bumped, and nothing bumps these.
- **Testnet only.** No pubnet deployment exists, and the points above are why
  one would be premature.
