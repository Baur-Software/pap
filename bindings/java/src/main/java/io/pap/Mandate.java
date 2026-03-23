package io.pap;

import com.sun.jna.Pointer;

/**
 * Core delegation primitive. Signed by the issuer's key; verifiable
 * back to the root principal key.
 *
 * <h3>Decay state safety</h3>
 *
 * <p>The decay state in a mandate serialized to JSON is <em>not</em> covered
 * by the Ed25519 signature. Never trust a deserialized decay state from the
 * wire — always call {@link #syncDecayState(long)} after deserialization.</p>
 *
 * <p>Prefer {@link #syncDecayState(long)} over {@link #transitionDecay(DecayState)}
 * for time-driven state changes. It handles two traps automatically:</p>
 *
 * <ol>
 *   <li><b>TTL-expiry jump</b>: if the TTL expires between polling cycles while
 *   the state is {@link DecayState#ACTIVE}, the computed state jumps to
 *   {@link DecayState#READ_ONLY}. Since {@code ACTIVE → READ_ONLY} is not a
 *   valid single-step transition, the C layer inserts the intermediate
 *   {@code DEGRADED} step automatically.</li>
 *
 *   <li><b>Self-transition guard</b>: {@code transitionDecay} rejects X→X
 *   transitions. {@code syncDecayState} is a no-op when the computed state
 *   already equals the current state.</li>
 * </ol>
 *
 * <h3>Suspended is terminal</h3>
 * <p>Once a mandate reaches {@link DecayState#SUSPENDED} no further
 * transitions — including renewal — are possible. Check before attempting
 * any renewal flow.</p>
 */
public final class Mandate implements AutoCloseable {

    private final Pointer handle;

    private Mandate(Pointer h) {
        this.handle = h;
    }

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /**
     * Issue a root mandate directly by the principal.
     *
     * @param principalDid  did:key of the human principal (root of trust)
     * @param agentDid      did:key of the agent receiving the mandate
     * @param scope         permitted actions
     * @param disclosureSet context classes the agent may share
     * @param ttlRfc3339    RFC 3339 expiry, e.g. {@code "2026-03-22T12:00:00Z"}
     */
    public static Mandate issueRoot(
            String principalDid,
            String agentDid,
            Scope scope,
            DisclosureSet disclosureSet,
            String ttlRfc3339) {
        Pointer h = PapLib.INSTANCE.pap_mandate_issue_root(
                principalDid, agentDid,
                scope.raw(), disclosureSet.raw(),
                ttlRfc3339);
        if (h == null) throw PapException.fromLastError("mandate_issue_root");
        return new Mandate(h);
    }

    /**
     * Delegate a child mandate from this mandate.
     * Enforces: child scope ⊆ parent scope AND child TTL ≤ parent TTL.
     */
    public Mandate delegate(
            String agentDid,
            Scope scope,
            DisclosureSet disclosureSet,
            String ttlRfc3339) {
        Pointer h = PapLib.INSTANCE.pap_mandate_delegate(
                handle, agentDid,
                scope.raw(), disclosureSet.raw(),
                ttlRfc3339);
        if (h == null) throw PapException.fromLastError("mandate_delegate");
        return new Mandate(h);
    }

    // -----------------------------------------------------------------------
    // Signing and verification
    // -----------------------------------------------------------------------

    /** Sign the mandate with the issuer's keypair. Must be called before use. */
    public void sign(PrincipalKeypair keypair) {
        if (PapLib.INSTANCE.pap_mandate_sign(handle, keypair.raw()) != 0)
            throw PapException.fromLastError("mandate_sign");
    }

    /**
     * Verify the mandate's Ed25519 signature.
     *
     * @param pubkeyBytes exactly 32 bytes of the issuer's public key
     */
    public void verify(byte[] pubkeyBytes) {
        if (pubkeyBytes.length != 32)
            throw new IllegalArgumentException("Public key must be exactly 32 bytes");
        if (PapLib.INSTANCE.pap_mandate_verify(handle, pubkeyBytes, pubkeyBytes.length) != 0)
            throw PapException.fromLastError("mandate_verify");
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /** Serialize to a JSON string. */
    public String toJson() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_to_json(handle);
        if (ptr == null) throw PapException.fromLastError("mandate_to_json");
        String s = ptr.getString(0);
        PapLib.INSTANCE.pap_string_free(ptr);
        return s;
    }

    /**
     * Deserialize from a JSON string.
     *
     * <p><b>Important:</b> {@code decay_state} in the JSON is NOT covered by
     * the signature and must not be trusted from the wire. Always call
     * {@link #syncDecayState(long)} after deserialization.</p>
     */
    public static Mandate fromJson(String json) {
        Pointer h = PapLib.INSTANCE.pap_mandate_from_json(json);
        if (h == null) throw PapException.fromLastError("mandate_from_json");
        return new Mandate(h);
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /** SHA-256 hash (base64url) of the signed fields. Excludes decay_state and signature. */
    public String hash() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_hash(handle);
        if (ptr == null) throw PapException.fromLastError("mandate_hash");
        String s = ptr.getString(0);
        PapLib.INSTANCE.pap_string_free(ptr);
        return s;
    }

    /** Returns {@code true} if {@code now > TTL}. */
    public boolean isExpired() {
        return PapLib.INSTANCE.pap_mandate_is_expired(handle) == 1;
    }

    public String principalDid() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_principal_did(handle);
        if (ptr == null) throw PapException.fromLastError();
        String s = ptr.getString(0); PapLib.INSTANCE.pap_string_free(ptr); return s;
    }

    public String agentDid() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_agent_did(handle);
        if (ptr == null) throw PapException.fromLastError();
        String s = ptr.getString(0); PapLib.INSTANCE.pap_string_free(ptr); return s;
    }

    public String issuerDid() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_issuer_did(handle);
        if (ptr == null) throw PapException.fromLastError();
        String s = ptr.getString(0); PapLib.INSTANCE.pap_string_free(ptr); return s;
    }

    /** TTL as an RFC 3339 string. Use UTC when comparing with {@link java.time.Instant}. */
    public String ttl() {
        Pointer ptr = PapLib.INSTANCE.pap_mandate_ttl(handle);
        if (ptr == null) throw PapException.fromLastError();
        String s = ptr.getString(0); PapLib.INSTANCE.pap_string_free(ptr); return s;
    }

    // -----------------------------------------------------------------------
    // Decay state
    // -----------------------------------------------------------------------

    /**
     * Returns the current stored decay state.
     *
     * <p><b>Do not trust this value on a freshly deserialized mandate</b>
     * without first calling {@link #syncDecayState(long)}.</p>
     */
    public DecayState decayState() {
        int v = PapLib.INSTANCE.pap_mandate_decay_state(handle);
        if (v < 0) throw PapException.fromLastError("mandate_decay_state");
        return DecayState.fromInt(v);
    }

    /**
     * Compute the time-based decay state <em>without</em> mutating the mandate.
     *
     * @param decayWindowSecs seconds before TTL at which {@link DecayState#DEGRADED} begins
     * @return the computed state (does not update the stored state)
     */
    public DecayState computeDecayState(long decayWindowSecs) {
        int v = PapLib.INSTANCE.pap_mandate_compute_decay_state(handle, decayWindowSecs);
        if (v < 0) throw PapException.fromLastError("compute_decay_state");
        return DecayState.fromInt(v);
    }

    /**
     * Synchronize the stored decay state to the time-computed value.
     *
     * <p>This is the <em>safe</em> high-level method for all time-driven decay
     * changes. It handles two correctness traps:</p>
     *
     * <ol>
     *   <li><b>TTL-expiry jump</b>: if the TTL expires between polling cycles
     *   while the state is {@link DecayState#ACTIVE}, {@code computeDecayState}
     *   returns {@link DecayState#READ_ONLY}. {@code ACTIVE → READ_ONLY} is not
     *   a valid single-step transition per the PAP spec state machine, so the
     *   C layer inserts the intermediate {@link DecayState#DEGRADED} step.
     *   If you call {@link #transitionDecay(DecayState)} with
     *   {@code READ_ONLY} directly when the state is {@code ACTIVE}, you will
     *   get an {@link PapException}.</li>
     *
     *   <li><b>Self-transition guard</b>: the state machine rejects X→X
     *   transitions. This method is a no-op when the computed state already
     *   equals the current state, so it is safe to call on every polling tick.</li>
     * </ol>
     *
     * @param decayWindowSecs seconds before TTL at which DEGRADED begins
     */
    public void syncDecayState(long decayWindowSecs) {
        if (PapLib.INSTANCE.pap_mandate_sync_decay_state(handle, decayWindowSecs) != 0)
            throw PapException.fromLastError("sync_decay_state");
    }

    /**
     * Explicit single-step decay transition (validates via the spec state machine).
     *
     * <p>Use {@link #syncDecayState(long)} for time-driven changes.
     * Use this method for explicit renewal ({@link DecayState#DEGRADED} →
     * {@link DecayState#ACTIVE} or {@link DecayState#READ_ONLY} →
     * {@link DecayState#ACTIVE}) and manual suspension flows.</p>
     *
     * <p><b>Important:</b> do not call with the current state — self-transitions
     * are rejected. Check {@link #decayState()} first.</p>
     *
     * <p><b>Suspended is terminal.</b> Once a mandate is
     * {@link DecayState#SUSPENDED}, no transitions — including renewal — are
     * possible.</p>
     */
    public void transitionDecay(DecayState next) {
        if (PapLib.INSTANCE.pap_mandate_transition_decay(handle, next.value) != 0)
            throw PapException.fromLastError("transition_decay");
    }

    // -----------------------------------------------------------------------
    // Resource management
    // -----------------------------------------------------------------------

    Pointer raw() { return handle; }

    @Override
    public void close() {
        PapLib.INSTANCE.pap_mandate_free(handle);
    }
}
