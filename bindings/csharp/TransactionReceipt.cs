using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// Co-signed transaction receipt containing property references only.
/// Built from an executed session; auditable by both principals.
/// </summary>
public sealed class TransactionReceipt : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_receipt_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private TransactionReceipt(IntPtr h) => _handle = new Handle(h);

    /// <summary>
    /// Create a receipt from an executed session.
    /// </summary>
    public static TransactionReceipt FromSession(
        Session session,
        string[] disclosedByInitiator,
        string[] disclosedByReceiver,
        string executed,
        string returned)
    {
        var initPtrs = AllocCStrings(disclosedByInitiator);
        var recvPtrs = AllocCStrings(disclosedByReceiver);
        try
        {
            var h = PapNative.pap_receipt_from_session(
                session.Raw,
                initPtrs, (nuint)initPtrs.Length,
                recvPtrs, (nuint)recvPtrs.Length,
                executed, returned);
            if (h == IntPtr.Zero) PapNative.ThrowLastError("receipt_from_session");
            return new TransactionReceipt(h);
        }
        finally
        {
            FreeCStrings(initPtrs);
            FreeCStrings(recvPtrs);
        }
    }

    /// <summary>Co-sign the receipt with a session/principal keypair.</summary>
    public void CoSign(PrincipalKeypair keypair)
    {
        if (PapNative.pap_receipt_co_sign(Raw, keypair.Raw) != 0)
            PapNative.ThrowLastError("receipt_co_sign");
    }

    /// <summary>Verify a specific co-signature by index.</summary>
    public void VerifySignature(int index, byte[] pubkeyBytes)
    {
        if (PapNative.pap_receipt_verify_signature(Raw, (nuint)index, pubkeyBytes, (nuint)pubkeyBytes.Length) != 0)
            PapNative.ThrowLastError("receipt_verify_signature");
    }

    /// <summary>Verify both co-signatures.</summary>
    public void VerifyBoth(byte[] initiatorPubkey, byte[] receiverPubkey)
    {
        if (PapNative.pap_receipt_verify_both(
                Raw,
                initiatorPubkey, (nuint)initiatorPubkey.Length,
                receiverPubkey, (nuint)receiverPubkey.Length) != 0)
            PapNative.ThrowLastError("receipt_verify_both");
    }

    /// <summary>Serialize to a JSON string.</summary>
    public string ToJson() => PapNative.OwnedString(PapNative.pap_receipt_to_json(Raw));

    /// <summary>Deserialize from a JSON string.</summary>
    public static TransactionReceipt FromJson(string json)
    {
        var h = PapNative.pap_receipt_from_json(json);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("receipt_from_json");
        return new TransactionReceipt(h);
    }

    /// <summary>The ephemeral session ID.</summary>
    public string SessionId => PapNative.OwnedString(PapNative.pap_receipt_session_id(Raw));

    /// <summary>The Schema.org action reference.</summary>
    public string Action => PapNative.OwnedString(PapNative.pap_receipt_action(Raw));

    /// <summary>Number of co-signatures.</summary>
    public int SignatureCount => PapNative.pap_receipt_signature_count(Raw);

    public void Dispose() => _handle.Dispose();

    private static IntPtr[] AllocCStrings(string[] strings)
    {
        var ptrs = new IntPtr[strings.Length];
        for (int i = 0; i < strings.Length; i++)
            ptrs[i] = Marshal.StringToCoTaskMemUTF8(strings[i]);
        return ptrs;
    }

    private static void FreeCStrings(IntPtr[] ptrs)
    {
        foreach (var p in ptrs)
            if (p != IntPtr.Zero) Marshal.FreeCoTaskMem(p);
    }
}
