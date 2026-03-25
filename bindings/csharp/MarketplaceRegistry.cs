using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>
/// Local marketplace registry for agent advertisements.
/// Supports registration and query by Schema.org action type.
/// </summary>
public sealed class MarketplaceRegistry : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_registry_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    /// <summary>Create an empty marketplace registry.</summary>
    public MarketplaceRegistry()
    {
        var h = PapNative.pap_registry_new();
        if (h == IntPtr.Zero) PapNative.ThrowLastError("registry_new");
        _handle = new Handle(h);
    }

    /// <summary>
    /// Register an advertisement. The advertisement must be signed.
    /// Throws <see cref="PapException"/> if unsigned.
    /// </summary>
    public void Register(AgentAdvertisement ad)
    {
        if (PapNative.pap_registry_register(Raw, ad.Raw) != 0)
            PapNative.ThrowLastError("registry_register");
    }

    /// <summary>
    /// Query for advertisements matching the given Schema.org action.
    /// Returns JSON array of matching advertisements.
    /// </summary>
    public string QueryByAction(string action)
        => PapNative.OwnedString(PapNative.pap_registry_query_by_action(Raw, action));

    /// <summary>Number of registered advertisements.</summary>
    public int Count => PapNative.pap_registry_len(Raw);

    public void Dispose() => _handle.Dispose();
}
