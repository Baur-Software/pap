package io.pap;

import com.sun.jna.Pointer;

/**
 * Deny-by-default set of permitted Schema.org actions.
 * An agent can only perform actions explicitly listed in its mandate scope.
 */
public final class Scope implements AutoCloseable {

    private final Pointer handle;

    private Scope(Pointer h) {
        this.handle = h;
    }

    /**
     * Build a scope from a flat list of action names (no object constraints).
     * This is the common case — each string is one permitted Schema.org action.
     *
     * <pre>{@code
     * Scope s = Scope.from(new String[]{
     *     "schema:SearchAction",
     *     "schema:ReserveAction"
     * });
     * }</pre>
     *
     * An empty array creates a deny-all scope (nothing permitted).
     */
    public static Scope from(String[] actions) {
        String[][] pairs = new String[actions.length][];
        for (int i = 0; i < actions.length; i++) {
            pairs[i] = new String[]{actions[i]};
        }
        return from(pairs);
    }

    /**
     * Build a scope from a list of (action, optional-object) pairs.
     * Use {@code null} for the object when there is no constraint.
     *
     * <pre>{@code
     * Scope s = Scope.from(
     *     new String[]{"schema:SearchAction", null},
     *     new String[]{"schema:ReserveAction", "schema:Flight"}
     * );
     * }</pre>
     */
    public static Scope from(String[]... actionPairs) {
        Pointer[] actionHandles = new Pointer[actionPairs.length];
        for (int i = 0; i < actionPairs.length; i++) {
            String action = actionPairs[i][0];
            String object = actionPairs[i].length > 1 ? actionPairs[i][1] : null;
            Pointer a = object == null
                    ? PapLib.INSTANCE.pap_scope_action_new(action)
                    : PapLib.INSTANCE.pap_scope_action_with_object(action, object);
            if (a == null) {
                for (int j = 0; j < i; j++) PapLib.INSTANCE.pap_scope_action_free(actionHandles[j]);
                throw PapException.fromLastError("scope_action_new");
            }
            actionHandles[i] = a;
        }
        Pointer h = PapLib.INSTANCE.pap_scope_new(actionHandles, actionHandles.length);
        for (Pointer a : actionHandles) PapLib.INSTANCE.pap_scope_action_free(a);
        if (h == null) throw PapException.fromLastError("scope_new");
        return new Scope(h);
    }

    /** Create a deny-all scope. */
    public static Scope denyAll() {
        Pointer h = PapLib.INSTANCE.pap_scope_deny_all();
        if (h == null) throw PapException.fromLastError("scope_deny_all");
        return new Scope(h);
    }

    /** Returns {@code true} if the scope permits {@code action}. */
    public boolean permits(String action) {
        return PapLib.INSTANCE.pap_scope_permits(handle, action) == 1;
    }

    /** Returns {@code true} if {@code child} ⊆ this scope. */
    public boolean contains(Scope child) {
        return PapLib.INSTANCE.pap_scope_contains(handle, child.handle) == 1;
    }

    Pointer raw() { return handle; }

    @Override
    public void close() {
        PapLib.INSTANCE.pap_scope_free(handle);
    }
}
