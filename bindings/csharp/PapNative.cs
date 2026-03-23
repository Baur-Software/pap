// PapNative.cs — P/Invoke declarations for libpap_c.
//
// The native library name is "pap_c". The .NET runtime resolves this to:
//   macOS  → libpap_c.dylib
//   Linux  → libpap_c.so
//   Windows → pap_c.dll
//
// Place the compiled library alongside the assembly, or set the library
// search path before calling any Pap API.

using System.Runtime.InteropServices;

namespace Pap;

internal static partial class PapNative
{
    private const string Lib = "pap_c";

    // ---- Error reporting --------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_last_error_message();

    [LibraryImport(Lib)]
    internal static partial void pap_string_free(IntPtr s);

    // ---- PrincipalKeypair -------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_keypair_generate();

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_keypair_from_bytes(
        [In] byte[] bytes, nuint len);

    [LibraryImport(Lib)]
    internal static partial void pap_keypair_free(IntPtr kp);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_keypair_did(IntPtr kp);

    [LibraryImport(Lib)]
    internal static partial int pap_keypair_public_bytes(
        IntPtr kp, [Out] byte[] outBuf);

    [LibraryImport(Lib)]
    internal static partial int pap_keypair_sign(
        IntPtr kp,
        [In] byte[] msg, nuint msgLen,
        [Out] byte[] sigOut);

    // ---- SessionKeypair ---------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_session_keypair_generate();

    [LibraryImport(Lib)]
    internal static partial void pap_session_keypair_free(IntPtr kp);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_session_keypair_did(IntPtr kp);

    // ---- DID utilities ----------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial int pap_did_to_public_key_bytes(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string did,
        [Out] byte[] outBuf);

    // ---- ScopeAction ------------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_scope_action_new(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string action);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_scope_action_with_object(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string action,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string obj);

    [LibraryImport(Lib)]
    internal static partial void pap_scope_action_free(IntPtr a);

    // ---- Scope ------------------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_scope_new(
        [In] IntPtr[] actions, nuint count);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_scope_deny_all();

    [LibraryImport(Lib)]
    internal static partial void pap_scope_free(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial int pap_scope_permits(
        IntPtr scope,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string action);

    [LibraryImport(Lib)]
    internal static partial int pap_scope_contains(
        IntPtr parent, IntPtr child);

    // ---- DisclosureSet ----------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_disclosure_set_empty();

    [LibraryImport(Lib)]
    internal static partial void pap_disclosure_set_free(IntPtr ds);

    // ---- Mandate ----------------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_issue_root(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string principalDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string agentDid,
        IntPtr scope,
        IntPtr disclosureSet,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string ttlRfc3339);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_delegate(
        IntPtr parent,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string agentDid,
        IntPtr scope,
        IntPtr disclosureSet,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string ttlRfc3339);

    [LibraryImport(Lib)]
    internal static partial void pap_mandate_free(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_sign(IntPtr m, IntPtr kp);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_verify(
        IntPtr m, [In] byte[] pubkeyBytes, nuint pubkeyLen);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_to_json(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_from_json(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string json);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_hash(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_decay_state(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_compute_decay_state(
        IntPtr m, long decayWindowSecs);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_transition_decay(
        IntPtr m, int nextState);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_sync_decay_state(
        IntPtr m, long decayWindowSecs);

    [LibraryImport(Lib)]
    internal static partial int pap_mandate_is_expired(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_principal_did(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_agent_did(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_issuer_did(IntPtr m);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_mandate_ttl(IntPtr m);

    // ---- CapabilityToken --------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_token_mint(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string targetDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string action,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string issuerDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string expiresAtRfc3339);

    [LibraryImport(Lib)]
    internal static partial void pap_token_free(IntPtr t);

    [LibraryImport(Lib)]
    internal static partial int pap_token_sign(IntPtr t, IntPtr kp);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_token_to_json(IntPtr t);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_token_from_json(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string json);

    // ---- Session ----------------------------------------------------------

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_session_initiate(
        IntPtr token,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string receiverDid,
        [In] byte[] issuerPubkey,
        nuint pubkeyLen);

    [LibraryImport(Lib)]
    internal static partial void pap_session_free(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial int pap_session_open(
        IntPtr s,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string initiatorDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string receiverDid);

    [LibraryImport(Lib)]
    internal static partial int pap_session_execute(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial int pap_session_close(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial int pap_session_state(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial IntPtr pap_session_id(IntPtr s);

    // ---- Helpers ----------------------------------------------------------

    /// Read a C string returned by the library, free it, return a managed string.
    internal static string OwnedString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero) ThrowLastError();
        var s = Marshal.PtrToStringUTF8(ptr)
                ?? throw new PapException("null string returned");
        pap_string_free(ptr);
        return s;
    }

    /// Throw a PapException populated from pap_last_error_message().
    internal static void ThrowLastError(string? context = null)
    {
        var ptr = pap_last_error_message();
        var msg = ptr != IntPtr.Zero ? Marshal.PtrToStringUTF8(ptr) ?? "unknown error" : "unknown error";
        if (ptr != IntPtr.Zero) pap_string_free(ptr);
        throw new PapException(context is null ? msg : $"{context}: {msg}");
    }
}
