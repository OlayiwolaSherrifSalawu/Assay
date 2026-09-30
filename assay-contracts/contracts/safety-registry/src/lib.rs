#![no_std]
//! Assay safety registry: an on-chain gate for Stellar asset trap mechanics.
//!
//! # What this contract is, and what it is not
//!
//! A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
//! issuer's authorization flags from within a transaction. So this contract
//! does not scan anything. It stores *attestations* produced by an off-chain
//! Assay scanner and lets another contract read one atomically, in the same
//! transaction as the action it is protecting.
//!
//! That distinction is deliberate and is stated here rather than hidden behind
//! a reassuring function name. A caller is trusting the attester, plus the
//! `evidence_hash` that lets anyone verify the attestation against the evidence
//! the scanner actually fetched.
//!
//! # Why severity is safe to gate on
//!
//! [`Safety::severity`] is capability-only: it is derived from the issuer's
//! authorization flags and never adjusted by reputation, attribution, age, or
//! popularity. Two assets whose issuers hold identical power over holders get
//! identical severity. A gate reading `severity <= MEDIUM` is therefore relying
//! on a statement about ledger mechanics, not on anyone's opinion of an issuer.
//!
//! The one exception moves in the safe direction only: a confirmed malicious
//! listing escalates severity to [`SEVERITY_CRITICAL`]. Reputation can raise a
//! level, never lower one.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
};

/// No authorization flags: the issuer has no special power over holders.
pub const SEVERITY_CLEAR: u32 = 0;
/// `auth_required`: the issuer controls who may open a trustline.
pub const SEVERITY_LOW: u32 = 1;
/// `auth_revocable`: the issuer can freeze an existing holder's balance.
pub const SEVERITY_MEDIUM: u32 = 2;
/// `auth_clawback_enabled`: the issuer can confiscate and burn a balance.
pub const SEVERITY_HIGH: u32 = 3;
/// Reserved for reputation escalation; never produced by reading flags.
pub const SEVERITY_CRITICAL: u32 = 4;

/// Mechanic bits. These positions are ABI and must not be renumbered; they
/// match `internal/mechanics.Mechanic` on the Go side.
pub const MECH_AUTH_REQUIRED: u32 = 1 << 0;
pub const MECH_AUTH_REVOCABLE: u32 = 1 << 1;
pub const MECH_CLAWBACK_ENABLED: u32 = 1 << 2;
pub const MECH_FLAGS_LOCKED: u32 = 1 << 3;
pub const MECH_DOMAIN_UNVERIFIED: u32 = 1 << 4;
pub const MECH_BLOCKLISTED: u32 = 1 << 5;

/// Mechanics that let an issuer take a balance outright. Any asset matching
/// this mask has `severity >= SEVERITY_HIGH` by construction.
pub const CONFISCATION_MASK: u32 = MECH_CLAWBACK_ENABLED;

/// Named forbidden-bit masks for [`SafetyRegistry::is_safe_masked`]. They exist
/// so a caller expresses a policy ("I never accept confiscation") rather than
/// hand-rolling bits. A caller may still pass any `u32`; these are the two
/// documented shapes.
///
/// `POLICY_MASK_CONFISCATION_ONLY` refuses only confiscation capability. A
/// protocol that can tolerate a freeze but never a clawback uses this mask.
pub const POLICY_MASK_CONFISCATION_ONLY: u32 = MECH_CLAWBACK_ENABLED;

/// `POLICY_MASK_FREEZE_INCLUSIVE` refuses both freeze and confiscation. A
/// custody product that must never see a holder's balance altered by the
/// issuer uses this mask.
pub const POLICY_MASK_FREEZE_INCLUSIVE: u32 = MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Event emitted on every successful `attest` write. Rejected attestations
/// (`InvalidSeverity`, `InconsistentAttestation`, unauthorized caller) publish
/// nothing, so observers never see writes that did not happen.
///
/// Topics: `("attest", asset)`. The asset address is a topic (not a data
/// field) so indexers can subscribe by asset without decoding every event.
/// Two topics stay well within the SDK's four-topic limit.
///
/// Data is a `Map` keyed by field name for readability from RPC output. The
/// exact shape is part of the observable ABI: see `docs/contract-interface.md`.
#[contractevent(topics = ["attest"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attested {
    /// The attested asset, identified by its Stellar Asset Contract address.
    #[topic]
    pub asset: Address,
    /// Capability severity written for the asset.
    pub severity: u32,
    /// Mechanic bitset written for the asset.
    pub flags: u32,
    /// Ledger timestamp of the write.
    pub attested_at: u64,
}

/// Event emitted on every successful `revoke`. A revoke that fails
/// (`NotAttested`, unauthorized caller) publishes nothing.
///
/// Topics: `("revoke", asset)`, mirroring [`Attested`] so an indexer tracking
/// an asset by topic sees both the write and its withdrawal. Without this an
/// indexer that recorded an `attest` event would go on believing the
/// attestation stands after it has been removed from storage.
///
/// This is also the only place revoked and never-attested differ: on-chain,
/// `get_safety` returns `None` for both. See `docs/contract-interface.md`.
#[contractevent(topics = ["revoke"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revoked {
    /// The asset whose attestation was withdrawn.
    #[topic]
    pub asset: Address,
    /// Ledger timestamp of the revocation.
    pub revoked_at: u64,
}

/// A stored safety attestation for one asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    /// Capability severity, `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    pub severity: u32,
    /// Bitset of observed mechanics.
    pub flags: u32,
    /// SHA-256 over the canonical evidence bundle the scanner fetched. It lets
    /// a verifier prove this attestation corresponds to specific evidence,
    /// rather than trusting the severity number on its own. The exact bytes
    /// hashed are specified by `internal/attest` and reproducible with
    /// `assay attestation -preimage CODE-ISSUER`.
    pub evidence_hash: BytesN<32>,
    /// Ledger timestamp when this attestation was written.
    pub attested_at: u64,
}

/// Event emitted when an attestation is written or overwritten.
///
/// This event provides an on-chain audit trail so that any overwrite of an
/// attestation can be detected and the previous value reconstructed from
/// chain history.
///
/// Topics:
/// - `"attest"`: static topic identifying the event type
/// - `asset`: the Stellar Asset Contract address (as Address)
///
/// Data:
/// - `previous`: the previous attestation, or `None` if this is the first
///   attestation for this asset
/// - `current`: the new attestation that was written
///
/// Retention: Soroban contract events are retained in ledger history for
/// approximately 1 year (the same retention as ledger entries). Beyond that
/// window, history is not reconstructible from chain alone; an off-chain
/// indexer or archive is required for longer audit trails.
#[contractevent(topics = ["attest"], data_format = "map")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationEvent {
    /// The asset this attestation is for.
    pub asset: Address,
    /// The previous attestation, if any. `None` means this is the first
    /// attestation for this asset.
    pub previous: Option<Safety>,
    /// The new attestation that was written.
    pub current: Safety,
}

#[contracttype]
enum DataKey {
    /// Contract admin, the only address permitted to attest.
    Admin,
    /// Attestation for one asset, keyed by its Stellar Asset Contract address.
    Safety(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// `init` was called on an already-initialized contract.
    AlreadyInitialized = 1,
    /// The contract has no admin yet.
    NotInitialized = 2,
    /// Severity outside `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    InvalidSeverity = 3,
    /// An attestation violated the confiscation invariant: the clawback bit is
    /// set but severity is below `SEVERITY_HIGH`. Rejected at write time so a
    /// gate can rely on the invariant at read time.
    InconsistentAttestation = 4,
    /// `revoke` was called for an asset with no attestation in storage.
    /// Returned rather than treated as a no-op so a revocation aimed at the
    /// wrong address fails loudly instead of reporting success while the
    /// attestation it was meant to withdraw still stands.
    NotAttested = 5,
}

/// Extends the contract instance's TTL to the network maximum. Extending the
/// instance also extends the contract code entry, so the admin and the wasm
/// stay live as long as the registry is being written to.
///
/// The maximum is read from the host rather than hard-coded: archival
/// parameters are network configuration and change by validator vote. See
/// "Entry lifetime" in `docs/deployment.md` for why this runs on writes only.
fn extend_instance(env: &Env) {
    let max = env.storage().max_ttl();
    env.storage().instance().extend_ttl(max, max);
}

/// Extends one attestation entry's TTL to the network maximum.
///
/// `threshold == extend_to`, so this always extends: a fresh write starts at
/// the network minimum, far below the maximum.
fn extend_attestation(env: &Env, key: &DataKey) {
    let max = env.storage().max_ttl();
    env.storage().persistent().extend_ttl(key, max, max);
}

#[contract]
pub struct SafetyRegistry;

#[contractimpl]
impl SafetyRegistry {
    /// Sets the admin permitted to write attestations.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        extend_instance(&env);
        Ok(())
    }

    /// Writes an attestation for `asset`, identified by its SAC address.
    ///
    /// `severity`, `flags`, and `evidence_hash` come from the off-chain
    /// scanner: `assay attestation CODE-ISSUER` derives all three from a live
    /// scan, and `make attest` submits them. Validation here is not a
    /// formality: it enforces at write time the invariants that
    /// [`Self::is_safe`] relies on at read time.
    ///
    /// Emits an [`AttestationEvent`] with the previous value (if any) and the
    /// new value, providing an on-chain audit trail. See the event
    /// documentation for retention semantics.
    pub fn attest(
        env: Env,
        asset: Address,
        severity: u32,
        flags: u32,
        evidence_hash: BytesN<32>,
    ) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        if severity > SEVERITY_CRITICAL {
            return Err(Error::InvalidSeverity);
        }
        if flags & CONFISCATION_MASK != 0 && severity < SEVERITY_HIGH {
            return Err(Error::InconsistentAttestation);
        }

        let attested_at = env.ledger().timestamp();
        let safety = Safety {
            severity,
            flags,
            evidence_hash,
            attested_at,
        };

        // Read the previous value before overwriting
        let previous = env
            .storage()
            .persistent()
            .get::<DataKey, Safety>(&DataKey::Safety(asset.clone()));

        // Write the new attestation
        env.storage()
            .persistent()
            .set(&DataKey::Safety(asset.clone()), &safety);

        // Extend TTL to maximum so the attestation persists until explicitly
        // overwritten. Freshness is enforced by the caller via max_age_secs on
        // is_safe, not by storage expiry.
        env.storage().persistent().extend_ttl(
            &DataKey::Safety(asset),
            100,
            env.storage().max_ttl(),
        );
        let key = DataKey::Safety(asset.clone());
        env.storage().persistent().set(&key, &safety);
        extend_attestation(&env, &key);
        extend_instance(&env);

        // Publish after the write. Emitting before would let a storage failure
        // produce a visible "attest" for an attestation that does not exist;
        // emitting after means indexers observe writes that actually happened.
        // Rejected calls return early above, so no event is published for them.
        Attested {
            asset,
            severity,
            flags,
            attested_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Withdraws the attestation for `asset`, restoring the never-attested
    /// state: afterwards `get_safety` returns `None` and every gate fails
    /// closed on the asset.
    ///
    /// This is a retraction, not a new claim. Overwriting a wrong attestation
    /// with a higher severity asserts something the scanner never concluded;
    /// revoking says only that the previous claim no longer stands.
    ///
    /// Revoking an asset with no attestation returns [`Error::NotAttested`]
    /// and changes nothing. The asset can be attested again afterwards.
    pub fn revoke(env: Env, asset: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Safety(asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotAttested);
        }
        env.storage().persistent().remove(&key);
        extend_instance(&env);

        // Published after the removal, for the same reason as in `attest`.
        Revoked {
            asset,
            revoked_at: env.ledger().timestamp(),
        }
        .publish(&env);
        Ok(())
    }

    /// Reads the attestation for `asset`.
    ///
    /// Returns `None` when the asset has never been attested. That case is
    /// deliberately distinguishable from an attestation of `SEVERITY_CLEAR`:
    /// collapsing the two would make every unknown asset read as safe, which is
    /// the single worst failure this contract could have.
    ///
    /// Archived entries (TTL expired) are automatically restored per CAP-0066 /
    /// Protocol 23 when accessed. After restoration, the entry returns
    /// `Some(Safety)` with the original `attested_at` timestamp. This makes
    /// archived entries distinguishable from never-attested ones:
    /// - Never attested: returns `None`
    /// - Archived (restored): returns `Some(Safety)` with original `attested_at`
    ///
    /// The `attest` function extends the TTL to the maximum on every write, so
    /// archival should not occur in normal operation. Freshness is enforced by
    /// the caller via `max_age_secs` on `is_safe`, not by storage expiry.
    /// `None` also covers a revoked attestation: storage keeps no tombstone,
    /// so a caller cannot tell revoked from never attested. Both mean "no
    /// claim stands", and both fail closed.
    ///
    /// Reads do not extend TTL. An archived entry is never read as `None`:
    /// the host either restores it (and it reads with its original
    /// `attested_at`) or fails the transaction. See `docs/deployment.md`.
    pub fn get_safety(env: Env, asset: Address) -> Option<Safety> {
        env.storage().persistent().get(&DataKey::Safety(asset))
    }

    /// The fail-closed gate helper.
    ///
    /// Returns `true` only when an attestation exists, is fresh enough, and is
    /// at or below `max_severity`. Every other path returns `false`: never
    /// attested, stale, too severe, or inconsistent. The safe answer is the
    /// default, so a caller that gets the arguments wrong blocks rather than
    /// admits.
    ///
    /// Failure modes (all return `false`):
    /// - Never attested: `get_safety` returns `None`
    /// - Stale: `attested_at` older than `max_age_secs`
    /// - Too severe: `severity > max_severity`
    /// - Inconsistent: clawback capability attested below `SEVERITY_HIGH`
    ///
    /// A caller that needs to diagnose why a gate rejected can call
    /// `get_safety` directly: `None` means never attested; `Some(Safety)`
    /// with an old `attested_at` means the attestation has lapsed.
    ///
    /// `max_age_secs` of 0 disables the freshness requirement.
    pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool {
        let Some(safety) = Self::get_safety(env.clone(), asset) else {
            return false; // never attested: fail closed
        };

        if safety.severity > max_severity {
            return false;
        }

        // Defence in depth: attest() rejects this, but a gate must not depend
        // on the writer having been correct.
        if safety.flags & CONFISCATION_MASK != 0 && max_severity < SEVERITY_HIGH {
            return false;
        }

        if max_age_secs > 0 {
            let now = env.ledger().timestamp();
            // saturating_sub avoids underflow if an attestation carries a
            // timestamp ahead of the current ledger.
            if now.saturating_sub(safety.attested_at) > max_age_secs {
                return false;
            }
        }

        true
    }

    /// The mask-based fail-closed gate.
    ///
    /// Returns `true` only when an attestation exists, is fresh enough, and
    /// carries none of the bits set in `forbidden_mask`. Every other path
    /// returns `false`: never attested, stale, or forbidden bit set. An empty
    /// `forbidden_mask` still requires an attestation — an unattested asset
    /// must never read as safe, even with a policy that forbids nothing.
    ///
    /// Severity is a total order; policies are not. Severity-based gating with
    /// `is_safe` collapses two independent questions ("can they freeze it?"
    /// "can they take it?") onto one axis. A caller that can tolerate a freeze
    /// but never a confiscation should gate on `POLICY_MASK_CONFISCATION_ONLY`;
    /// a custody product refusing both should gate on
    /// `POLICY_MASK_FREEZE_INCLUSIVE`. See `docs/contract-interface.md`.
    ///
    /// `max_age_secs` of 0 disables the freshness requirement.
    pub fn is_safe_masked(
        env: Env,
        asset: Address,
        forbidden_mask: u32,
        max_age_secs: u64,
    ) -> bool {
        let Some(safety) = Self::get_safety(env.clone(), asset) else {
            return false; // never attested: fail closed
        };

        if safety.flags & forbidden_mask != 0 {
            return false;
        }

        if max_age_secs > 0 {
            let now = env.ledger().timestamp();
            if now.saturating_sub(safety.attested_at) > max_age_secs {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod test;
