package io.pap;

/**
 * Session lifecycle states. Integer values match {@code PAP_SESSION_*} in {@code pap.h}.
 */
public enum SessionState {
    INITIATED(0),
    OPEN(1),
    EXECUTED(2),
    CLOSED(3);

    public final int value;

    SessionState(int value) {
        this.value = value;
    }

    public static SessionState fromInt(int v) {
        for (SessionState s : values()) {
            if (s.value == v) return s;
        }
        throw new IllegalArgumentException("Unknown session state integer: " + v);
    }
}
