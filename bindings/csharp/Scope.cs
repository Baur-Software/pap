using Microsoft.Win32.SafeHandles;

namespace Pap;

/// <summary>Deny-by-default set of permitted Schema.org actions.</summary>
public sealed class Scope : IDisposable
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr h) : base(ownsHandle: true) { SetHandle(h); }
        protected override bool ReleaseHandle() { PapNative.pap_scope_free(handle); return true; }
    }

    private readonly Handle _handle;
    internal IntPtr Raw => _handle.DangerousGetHandle();

    private Scope(IntPtr h) => _handle = new Handle(h);

    /// <summary>
    /// Build a scope from an array of (action, optional-object) tuples.
    /// Passing an empty array produces a deny-all scope.
    /// </summary>
    public static Scope From(params (string Action, string? Object)[] actions)
    {
        // Build and accumulate C-side action handles.
        var handles = new IntPtr[actions.Length];
        for (int i = 0; i < actions.Length; i++)
        {
            var (action, obj) = actions[i];
            handles[i] = obj is null
                ? PapNative.pap_scope_action_new(action)
                : PapNative.pap_scope_action_with_object(action, obj);

            if (handles[i] == IntPtr.Zero)
            {
                // Free already-created handles before throwing.
                for (int j = 0; j < i; j++) PapNative.pap_scope_action_free(handles[j]);
                PapNative.ThrowLastError("scope_action_new");
            }
        }

        // Build the Scope (clones the actions internally).
        var h = PapNative.pap_scope_new(handles, (nuint)handles.Length);
        foreach (var a in handles) PapNative.pap_scope_action_free(a);
        if (h == IntPtr.Zero) PapNative.ThrowLastError("scope_new");
        return new Scope(h);
    }

    /// <summary>Create a deny-all scope.</summary>
    public static Scope DenyAll()
    {
        var h = PapNative.pap_scope_deny_all();
        if (h == IntPtr.Zero) PapNative.ThrowLastError("scope_deny_all");
        return new Scope(h);
    }

    /// <summary>Returns <c>true</c> if the scope permits <paramref name="action"/>.</summary>
    public bool Permits(string action) =>
        PapNative.pap_scope_permits(Raw, action) == 1;

    /// <summary>Returns <c>true</c> if <paramref name="child"/> ⊆ this scope.</summary>
    public bool Contains(Scope child) =>
        PapNative.pap_scope_contains(Raw, child.Raw) == 1;

    public void Dispose() => _handle.Dispose();
}
