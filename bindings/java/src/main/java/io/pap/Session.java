package io.pap;

import com.sun.jna.Pointer;

/**
 * Protocol session state machine: Initiated → Open → Executed → Closed.
 * Ephemeral session DIDs are exchanged at Open and discarded at Closed.
 */
public final class Session implements AutoCloseable {

    private final Pointer handle;

    private Session(Pointer h) {
        this.handle = h;
    }

    /**
     * Initiate a session from a capability token.
     *
     * @param token          a signed capability token
     * @param receiverDid    did:key of the receiver agent
     * @param issuerPubkey   32-byte Ed25519 public key of the token issuer,
     *                       used to verify the token signature
     */
    public static Session initiate(
            CapabilityToken token,
            String receiverDid,
            byte[] issuerPubkey) {
        if (issuerPubkey.length != 32)
            throw new IllegalArgumentException("Issuer public key must be exactly 32 bytes");
        Pointer h = PapLib.INSTANCE.pap_session_initiate(
                token.raw(), receiverDid, issuerPubkey, issuerPubkey.length);
        if (h == null) throw PapException.fromLastError("session_initiate");
        return new Session(h);
    }

    /**
     * Open the session by exchanging ephemeral session DIDs.
     * Both DIDs should be from freshly generated session keypairs.
     */
    public void open(String initiatorSessionDid, String receiverSessionDid) {
        if (PapLib.INSTANCE.pap_session_open(handle, initiatorSessionDid, receiverSessionDid) != 0)
            throw PapException.fromLastError("session_open");
    }

    /** Transition to Executed state. */
    public void execute() {
        if (PapLib.INSTANCE.pap_session_execute(handle) != 0)
            throw PapException.fromLastError("session_execute");
    }

    /** Close the session and discard ephemeral state. */
    public void close_session() {
        if (PapLib.INSTANCE.pap_session_close(handle) != 0)
            throw PapException.fromLastError("session_close");
    }

    /** Current session state. */
    public SessionState state() {
        int v = PapLib.INSTANCE.pap_session_state(handle);
        if (v < 0) throw PapException.fromLastError("session_state");
        return SessionState.fromInt(v);
    }

    /** The session UUID. */
    public String id() {
        Pointer ptr = PapLib.INSTANCE.pap_session_id(handle);
        if (ptr == null) throw PapException.fromLastError("session_id");
        String s = ptr.getString(0);
        PapLib.INSTANCE.pap_string_free(ptr);
        return s;
    }

    @Override
    public void close() {
        // Best-effort protocol close; ignore errors (e.g. already-closed state).
        PapLib.INSTANCE.pap_session_close(handle);
        PapLib.INSTANCE.pap_session_free(handle);
    }
}
