package io.pap;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * JNA interface that maps directly to the C symbols exported by libpap_c.
 *
 * <p>All methods here mirror the C ABI in {@code pap.h}. Consumers should
 * not use this interface directly; instead use the higher-level wrapper
 * classes ({@link PrincipalKeypair}, {@link Mandate}, etc.).</p>
 *
 * <h3>Memory contract</h3>
 * <ul>
 *   <li>Every {@code pap_*_generate / new / from_*} call returns a
 *       {@link Pointer} that the caller owns and must free via the
 *       corresponding {@code pap_*_free}.</li>
 *   <li>Strings returned as {@link Pointer} are heap-allocated C strings;
 *       free them with {@link #pap_string_free(Pointer)}.</li>
 *   <li>Input strings passed as {@code String} are marshalled by JNA and
 *       do not need to be freed.</li>
 * </ul>
 */
public interface PapLib extends Library {

    /** Singleton loaded from "pap_c" (libpap_c.so / .dylib / .dll). */
    PapLib INSTANCE = Native.load("pap_c", PapLib.class);

    // -----------------------------------------------------------------------
    // Error reporting
    // -----------------------------------------------------------------------

    /** Returns a heap-allocated error string, or NULL. Free with {@link #pap_string_free}. */
    Pointer pap_last_error_message();

    /** Free a string previously returned by any {@code pap_*} function. */
    void pap_string_free(Pointer s);

    // -----------------------------------------------------------------------
    // PrincipalKeypair
    // -----------------------------------------------------------------------

    Pointer pap_keypair_generate();
    Pointer pap_keypair_from_bytes(byte[] bytes, long len);
    void    pap_keypair_free(Pointer kp);
    Pointer pap_keypair_did(Pointer kp);
    int     pap_keypair_public_bytes(Pointer kp, byte[] out);
    int     pap_keypair_sign(Pointer kp, byte[] msg, long msgLen, byte[] sigOut);

    // -----------------------------------------------------------------------
    // SessionKeypair
    // -----------------------------------------------------------------------

    Pointer pap_session_keypair_generate();
    void    pap_session_keypair_free(Pointer kp);
    Pointer pap_session_keypair_did(Pointer kp);

    // -----------------------------------------------------------------------
    // DID utilities
    // -----------------------------------------------------------------------

    int pap_did_to_public_key_bytes(String did, byte[] out);

    // -----------------------------------------------------------------------
    // ScopeAction
    // -----------------------------------------------------------------------

    Pointer pap_scope_action_new(String action);
    Pointer pap_scope_action_with_object(String action, String object);
    void    pap_scope_action_free(Pointer a);

    // -----------------------------------------------------------------------
    // Scope
    // -----------------------------------------------------------------------

    Pointer pap_scope_new(Pointer[] actions, long count);
    Pointer pap_scope_deny_all();
    void    pap_scope_free(Pointer s);
    int     pap_scope_permits(Pointer scope, String action);
    int     pap_scope_contains(Pointer parent, Pointer child);

    // -----------------------------------------------------------------------
    // DisclosureEntry
    // -----------------------------------------------------------------------

    Pointer pap_disclosure_entry_new(
            String schemaType,
            String[] permitted,  long permittedCount,
            String[] prohibited, long prohibitedCount);
    int  pap_disclosure_entry_set_session_only(Pointer e, int sessionOnly);
    int  pap_disclosure_entry_set_no_retention(Pointer e, int noRetention);
    void pap_disclosure_entry_free(Pointer e);

    // -----------------------------------------------------------------------
    // DisclosureSet
    // -----------------------------------------------------------------------

    Pointer pap_disclosure_set_empty();
    Pointer pap_disclosure_set_new(Pointer[] entries, long count);
    void    pap_disclosure_set_free(Pointer ds);

    // -----------------------------------------------------------------------
    // Mandate
    // -----------------------------------------------------------------------

    Pointer pap_mandate_issue_root(
            String principalDid, String agentDid,
            Pointer scope, Pointer disclosureSet,
            String ttlRfc3339);

    Pointer pap_mandate_delegate(
            Pointer parent, String agentDid,
            Pointer scope, Pointer disclosureSet,
            String ttlRfc3339);

    void    pap_mandate_free(Pointer m);
    int     pap_mandate_sign(Pointer m, Pointer kp);
    int     pap_mandate_verify(Pointer m, byte[] pubkeyBytes, long pubkeyLen);
    Pointer pap_mandate_to_json(Pointer m);
    Pointer pap_mandate_from_json(String json);
    Pointer pap_mandate_hash(Pointer m);
    int     pap_mandate_decay_state(Pointer m);
    int     pap_mandate_compute_decay_state(Pointer m, long decayWindowSecs);
    int     pap_mandate_transition_decay(Pointer m, int nextState);
    int     pap_mandate_sync_decay_state(Pointer m, long decayWindowSecs);
    int     pap_mandate_is_expired(Pointer m);
    Pointer pap_mandate_principal_did(Pointer m);
    Pointer pap_mandate_agent_did(Pointer m);
    Pointer pap_mandate_issuer_did(Pointer m);
    Pointer pap_mandate_ttl(Pointer m);

    // -----------------------------------------------------------------------
    // CapabilityToken
    // -----------------------------------------------------------------------

    Pointer pap_token_mint(String targetDid, String action,
                           String issuerDid, String expiresAtRfc3339);
    void    pap_token_free(Pointer t);
    int     pap_token_sign(Pointer t, Pointer kp);
    Pointer pap_token_to_json(Pointer t);
    Pointer pap_token_from_json(String json);

    // -----------------------------------------------------------------------
    // Session
    // -----------------------------------------------------------------------

    Pointer pap_session_initiate(
            Pointer token, String receiverDid,
            byte[] issuerPubkey, long pubkeyLen);
    void    pap_session_free(Pointer s);
    int     pap_session_open(Pointer s,
                             String initiatorSessionDid,
                             String receiverSessionDid);
    int     pap_session_execute(Pointer s);
    int     pap_session_close(Pointer s);
    int     pap_session_state(Pointer s);
    Pointer pap_session_id(Pointer s);
}
