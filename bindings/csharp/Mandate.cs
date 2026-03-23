using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// Decay state of a mandate, progressing as the TTL approaches and expires.
/// Transitions: Active → Degraded → ReadOnly → Suspended.
/// Renewal is possible from Degraded or ReadOnly back to Active.
/// Suspended is terminal — no further transitions.
/// </summary>
public enum DecayState
{
    Active    = 0,
    Degraded  = 1,
    ReadOnly  = 2,
    Suspended = 3,
}

/// <summary>
/// Core delegation primitive. Signed by the issuer's key; verifiable
/// back to the root principal key.
/// </summary>
public sealed class Mandate : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_mandate_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private Mandate(IntPtr h) => _handle = new Handle(h);

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /// <summary>
    /// Issue a root mandate directly by the principal.
    /// <paramref name="ttlRfc3339"/> is an RFC 3339 timestamp,
    /// e.g. <c>"2026-03-22T12:00:00Z"</c>.
    /// </summary>
    public static Mandate IssueRoot(
        string principalDid,
        string agentDid,
        Scope scope,
        DisclosureSet disclosureSet,
        string ttlRfc3339)
    {
        var h = PapNative.pap_mandate_issue_root(
            principalDid, agentDid, scope.Raw, disclosureSet.Raw, ttlRfc3339);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("mandate_issue_root");
        return new Mandate(h);
    }

    /// <summary>
    /// Delegate a child mandate from this mandate.
    /// Enforces: child scope ⊆ parent scope AND child TTL ≤ parent TTL.
    /// </summary>
    public Mandate Delegate(
        string agentDid,
        Scope scope,
        DisclosureSet disclosureSet,
        string ttlRfc3339)
    {
        var h = PapNative.pap_mandate_delegate(
            Raw, agentDid, scope.Raw, disclosureSet.Raw, ttlRfc3339);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("mandate_delegate");
        return new Mandate(h);
    }

    // -----------------------------------------------------------------------
    // Signing and verification
    // -----------------------------------------------------------------------

    /// <summary>Sign the mandate with the issuer's keypair.</summary>
    public void Sign(PrincipalKeypair keypair)
    {
        if (PapNative.pap_mandate_sign(Raw, keypair.Raw) != 0)
            PapNative.ThrowLastError("mandate_sign");
    }

    /// <summary>Verify the mandate's signature against <paramref name="pubkeyBytes"/> (32 bytes).</summary>
    public void Verify(byte[] pubkeyBytes)
    {
        if (pubkeyBytes.Length != 32)
            throw new ArgumentException("Public key must be exactly 32 bytes.", nameof(pubkeyBytes));
        if (PapNative.pap_mandate_verify(Raw, pubkeyBytes, (nuint)pubkeyBytes.Length) != 0)
            PapNative.ThrowLastError("mandate_verify");
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// <summary>Serialize to a JSON string.</summary>
    public string ToJson() => PapNative.OwnedString(PapNative.pap_mandate_to_json(Raw));

    /// <summary>
    /// Deserialize from a JSON string.
    /// <para>
    /// <b>Important:</b> <c>decay_state</c> in the JSON is NOT covered by the
    /// signature and must not be trusted as-is. Always call
    /// <see cref="SyncDecayState"/> after deserialization.
    /// </para>
    /// </summary>
    public static Mandate FromJson(string json)
    {
        var h = PapNative.pap_mandate_from_json(json);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("mandate_from_json");
        return new Mandate(h);
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /// <summary>SHA-256 hash (base64url) of the signed fields. Excludes decay_state and signature.</summary>
    public string Hash() => PapNative.OwnedString(PapNative.pap_mandate_hash(Raw));

    /// <summary>Returns <c>true</c> if <c>now &gt; TTL</c>.</summary>
    public bool IsExpired() => PapNative.pap_mandate_is_expired(Raw) == 1;

    public string PrincipalDid => PapNative.OwnedString(PapNative.pap_mandate_principal_did(Raw));
    public string AgentDid     => PapNative.OwnedString(PapNative.pap_mandate_agent_did(Raw));
    public string IssuerDid    => PapNative.OwnedString(PapNative.pap_mandate_issuer_did(Raw));
    public string Ttl          => PapNative.OwnedString(PapNative.pap_mandate_ttl(Raw));

    // -----------------------------------------------------------------------
    // Decay state
    // -----------------------------------------------------------------------

    /// <summary>
    /// Current stored decay state.
    /// </summary>
    public DecayState DecayState
    {
        get
        {
            int v = PapNative.pap_mandate_decay_state(Raw);
            if (v < 0) PapNative.ThrowLastError("mandate_decay_state");
            return (DecayState)v;
        }
    }

    /// <summary>
    /// Compute the time-based decay state without mutating the mandate.
    /// <paramref name="decayWindowSecs"/> is seconds before TTL at which
    /// the state enters <see cref="DecayState.Degraded"/>.
    /// <para>
    /// This is a pure computation. Call <see cref="SyncDecayState"/> to apply.
    /// </para>
    /// </summary>
    public DecayState ComputeDecayState(long decayWindowSecs)
    {
        int v = PapNative.pap_mandate_compute_decay_state(Raw, decayWindowSecs);
        if (v < 0) PapNative.ThrowLastError("mandate_compute_decay_state");
        return (DecayState)v;
    }

    /// <summary>
    /// Synchronize the stored decay state to the time-computed value.
    /// <para>
    /// Handles two correctness traps automatically:
    /// <list type="number">
    ///   <item>
    ///     <b>TTL-expiry jump</b> — if the TTL expires between polling cycles
    ///     while the state is <see cref="DecayState.Active"/>, the computed
    ///     state jumps to <see cref="DecayState.ReadOnly"/>. Since
    ///     Active→ReadOnly is not a valid single-step transition, this method
    ///     inserts the intermediate <see cref="DecayState.Degraded"/> step.
    ///   </item>
    ///   <item>
    ///     <b>Self-transition guard</b> — <see cref="TransitionDecay"/> rejects
    ///     X→X; this method is a no-op when the computed state equals the
    ///     current state.
    ///   </item>
    /// </list>
    /// </para>
    /// </summary>
    public void SyncDecayState(long decayWindowSecs)
    {
        if (PapNative.pap_mandate_sync_decay_state(Raw, decayWindowSecs) != 0)
            PapNative.ThrowLastError("sync_decay_state");
    }

    /// <summary>
    /// Explicit single-step transition (validates via the spec state machine).
    /// <para>
    /// Use <see cref="SyncDecayState"/> for time-driven decay. Use this for
    /// explicit renewal (<see cref="DecayState.Degraded"/> →
    /// <see cref="DecayState.Active"/>) or suspension flows.
    /// </para>
    /// <para>
    /// <b>Do not call with the current state</b> — the state machine rejects
    /// self-transitions. Check <see cref="DecayState"/> first.
    /// </para>
    /// </summary>
    public void TransitionDecay(DecayState next)
    {
        if (PapNative.pap_mandate_transition_decay(Raw, (int)next) != 0)
            PapNative.ThrowLastError("transition_decay");
    }

    public void Dispose() => _handle.Dispose();
}
