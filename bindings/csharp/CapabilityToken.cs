using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// Single-use proof authorizing a session.
/// Bound to: target DID + action + nonce.
/// </summary>
public sealed class CapabilityToken : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_token_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private CapabilityToken(IntPtr h) => _handle = new Handle(h);

    /// <summary>
    /// Mint a new capability token.
    /// <paramref name="expiresAtRfc3339"/> is an RFC 3339 timestamp.
    /// </summary>
    public static CapabilityToken Mint(
        string targetDid, string action, string issuerDid, string expiresAtRfc3339)
    {
        var h = PapNative.pap_token_mint(targetDid, action, issuerDid, expiresAtRfc3339);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("token_mint");
        return new CapabilityToken(h);
    }

    /// <summary>Sign the token with the issuer's keypair.</summary>
    public void Sign(PrincipalKeypair keypair)
    {
        if (PapNative.pap_token_sign(Raw, keypair.Raw) != 0)
            PapNative.ThrowLastError("token_sign");
    }

    /// <summary>Serialize to a JSON string.</summary>
    public string ToJson() => PapNative.OwnedString(PapNative.pap_token_to_json(Raw));

    /// <summary>Deserialize from a JSON string.</summary>
    public static CapabilityToken FromJson(string json)
    {
        var h = PapNative.pap_token_from_json(json);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("token_from_json");
        return new CapabilityToken(h);
    }

    public void Dispose() => _handle.Dispose();
}
