using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// A signed JSON-LD agent advertisement describing capabilities,
/// disclosure requirements, and return types.
/// </summary>
public sealed class AgentAdvertisement : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_advertisement_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private AgentAdvertisement(IntPtr h) => _handle = new Handle(h);

    /// <summary>Create a new agent advertisement.</summary>
    public AgentAdvertisement(
        string name,
        string providerName,
        string operatorDid,
        string[] capability,
        string[] objectTypes,
        string[] requiresDisclosure,
        string[] returns)
    {
        var capPtrs = AllocCStrings(capability);
        var objPtrs = AllocCStrings(objectTypes);
        var discPtrs = AllocCStrings(requiresDisclosure);
        var retPtrs = AllocCStrings(returns);
        try
        {
            var h = PapNative.pap_advertisement_new(
                name, providerName, operatorDid,
                capPtrs, (nuint)capPtrs.Length,
                objPtrs, (nuint)objPtrs.Length,
                discPtrs, (nuint)discPtrs.Length,
                retPtrs, (nuint)retPtrs.Length);
            if (h == IntPtr.Zero) PapNative.ThrowLastError("advertisement_new");
            _handle = new Handle(h);
        }
        finally
        {
            FreeCStrings(capPtrs);
            FreeCStrings(objPtrs);
            FreeCStrings(discPtrs);
            FreeCStrings(retPtrs);
        }
    }

    /// <summary>Sign the advertisement with the operator's keypair.</summary>
    public void Sign(PrincipalKeypair keypair)
    {
        if (PapNative.pap_advertisement_sign(Raw, keypair.Raw) != 0)
            PapNative.ThrowLastError("advertisement_sign");
    }

    /// <summary>Verify the advertisement's signature.</summary>
    public void Verify(byte[] pubkeyBytes)
    {
        if (PapNative.pap_advertisement_verify(Raw, pubkeyBytes, (nuint)pubkeyBytes.Length) != 0)
            PapNative.ThrowLastError("advertisement_verify");
    }

    /// <summary>Returns true if the advertisement supports the given action.</summary>
    public bool SupportsAction(string action)
        => PapNative.pap_advertisement_supports_action(Raw, action) == 1;

    /// <summary>Serialize to a JSON string.</summary>
    public string ToJson() => PapNative.OwnedString(PapNative.pap_advertisement_to_json(Raw));

    /// <summary>Deserialize from a JSON string.</summary>
    public static AgentAdvertisement FromJson(string json)
    {
        var h = PapNative.pap_advertisement_from_json(json);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("advertisement_from_json");
        return new AgentAdvertisement(h);
    }

    /// <summary>The advertisement's human-readable name.</summary>
    public string Name => PapNative.OwnedString(PapNative.pap_advertisement_name(Raw));

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
