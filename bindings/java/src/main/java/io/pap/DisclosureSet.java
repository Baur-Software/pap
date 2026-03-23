package io.pap;

import com.sun.jna.Pointer;

/** Collection of context-class entries for a mandate. */
public final class DisclosureSet implements AutoCloseable {

    private final Pointer handle;

    private DisclosureSet(Pointer h) {
        this.handle = h;
    }

    /** Create an empty set (disclose nothing). */
    public static DisclosureSet empty() {
        Pointer h = PapLib.INSTANCE.pap_disclosure_set_empty();
        if (h == null) throw PapException.fromLastError("disclosure_set_empty");
        return new DisclosureSet(h);
    }

    Pointer raw() { return handle; }

    @Override
    public void close() {
        PapLib.INSTANCE.pap_disclosure_set_free(handle);
    }
}
