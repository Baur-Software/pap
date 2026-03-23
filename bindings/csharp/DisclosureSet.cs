using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>Collection of context-class entries for a mandate.</summary>
public sealed class DisclosureSet : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle()
        {
            PapNative.pap_disclosure_set_free(handle);
            return true;
        }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private DisclosureSet(IntPtr h) => _handle = new Handle(h);

    /// <summary>Create an empty set (disclose nothing).</summary>
    public static DisclosureSet Empty()
    {
        var h = PapNative.pap_disclosure_set_empty();
        if (h == IntPtr.Zero) PapNative.ThrowLastError("disclosure_set_empty");
        return new DisclosureSet(h);
    }

    public void Dispose() => _handle.Dispose();
}
