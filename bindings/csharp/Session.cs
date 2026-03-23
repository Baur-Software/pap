using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>Session lifecycle state.</summary>
public enum SessionState
{
    Initiated = 0,
    Open      = 1,
    Executed  = 2,
    Closed    = 3,
}

/// <summary>
/// Protocol session state machine: Initiated → Open → Executed → Closed.
/// Ephemeral session DIDs are exchanged at Open and discarded at Closed.
/// </summary>
public sealed class Session : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_session_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private Session(IntPtr h) => _handle = new Handle(h);

    /// <summary>
    /// Initiate a session from a capability token.
    /// <paramref name="issuerPublicKey"/> must be exactly 32 bytes (the
    /// Ed25519 public key of the token issuer, used to verify the signature).
    /// </summary>
    public static Session Initiate(
        CapabilityToken token,
        string receiverDid,
        byte[] issuerPublicKey)
    {
        if (issuerPublicKey.Length != 32)
            throw new ArgumentException("Issuer public key must be exactly 32 bytes.", nameof(issuerPublicKey));

        var h = PapNative.pap_session_initiate(
            token.Raw, receiverDid, issuerPublicKey, (nuint)issuerPublicKey.Length);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("session_initiate");
        return new Session(h);
    }

    /// <summary>
    /// Open the session by exchanging ephemeral session DIDs.
    /// Both DIDs should come from freshly-generated <c>SessionKeypair</c>s.
    /// </summary>
    public void Open(string initiatorSessionDid, string receiverSessionDid)
    {
        if (PapNative.pap_session_open(Raw, initiatorSessionDid, receiverSessionDid) != 0)
            PapNative.ThrowLastError("session_open");
    }

    /// <summary>Transition to Executed state.</summary>
    public void Execute()
    {
        if (PapNative.pap_session_execute(Raw) != 0)
            PapNative.ThrowLastError("session_execute");
    }

    /// <summary>Close the session and discard ephemeral state.</summary>
    public void Close()
    {
        if (PapNative.pap_session_close(Raw) != 0)
            PapNative.ThrowLastError("session_close");
    }

    /// <summary>Current session state.</summary>
    public SessionState State => (SessionState)PapNative.pap_session_state(Raw);

    /// <summary>The session UUID.</summary>
    public string Id => PapNative.OwnedString(PapNative.pap_session_id(Raw));

    public void Dispose() => _handle.Dispose();
}
