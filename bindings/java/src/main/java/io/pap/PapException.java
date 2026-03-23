package io.pap;

import com.sun.jna.Pointer;

/** Thrown by any PAP API call that fails at the protocol level. */
public class PapException extends RuntimeException {

    public PapException(String message) {
        super(message);
    }

    /**
     * Read the last error from the native library, free the C string,
     * and return a PapException with the message.
     * Includes an optional {@code context} prefix for easier debugging.
     */
    public static PapException fromLastError(String context) {
        Pointer ptr = PapLib.INSTANCE.pap_last_error_message();
        String msg = ptr != null ? ptr.getString(0) : "unknown PAP error";
        if (ptr != null) PapLib.INSTANCE.pap_string_free(ptr);
        String full = (context != null && !context.isEmpty())
                ? context + ": " + msg
                : msg;
        return new PapException(full);
    }

    public static PapException fromLastError() {
        return fromLastError(null);
    }
}
