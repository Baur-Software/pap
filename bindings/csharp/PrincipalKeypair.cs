using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// Root Ed25519 keypair bound to the human principal.
/// Implements <see cref="IDisposable"/>; wraps the native handle in a
/// <see cref="SafeHandle"/> for deterministic cleanup.
/// </summary>
public sealed class PrincipalKeypair : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_keypair_free(handle); return true; }
    }

    private readonly Handle _handle;

    internal IntPtr Raw => _handle.DangerousGetHandle();

    private PrincipalKeypair(IntPtr h) => _handle = new Handle(h);

    /// <summary>Generate a new random principal keypair.</summary>
    public static PrincipalKeypair Generate()
    {
        var h = PapNative.pap_keypair_generate();
        if (h == IntPtr.Zero) PapNative.ThrowLastError("keypair_generate");
        return new PrincipalKeypair(h);
    }

    /// <summary>Reconstruct from 32 raw secret-key bytes.</summary>
    public static PrincipalKeypair FromSecretBytes(byte[] bytes)
    {
        if (bytes.Length != 32)
            throw new ArgumentException("Secret key must be exactly 32 bytes.", nameof(bytes));
        var h = PapNative.pap_keypair_from_bytes(bytes, (nuint)bytes.Length);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("keypair_from_bytes");
        return new PrincipalKeypair(h);
    }

    /// <summary>The <c>did:key</c> identifier derived from this keypair.</summary>
    public string Did() => PapNative.OwnedString(PapNative.pap_keypair_did(Raw));

    /// <summary>The raw 32-byte public key.</summary>
    public byte[] PublicKeyBytes()
    {
        var buf = new byte[32];
        if (PapNative.pap_keypair_public_bytes(Raw, buf) != 0)
            PapNative.ThrowLastError("keypair_public_bytes");
        return buf;
    }

    /// <summary>Sign arbitrary bytes; returns the 64-byte Ed25519 signature.</summary>
    public byte[] Sign(byte[] message)
    {
        var sig = new byte[64];
        if (PapNative.pap_keypair_sign(Raw, message, (nuint)message.Length, sig) != 0)
            PapNative.ThrowLastError("keypair_sign");
        return sig;
    }

    public void Dispose() => _handle.Dispose();
}
