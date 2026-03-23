package io.pap;

/**
 * Decay state for a mandate's scope as TTL progresses without renewal.
 *
 * <p>Valid transitions:</p>
 * <ul>
 *   <li>Active → Degraded</li>
 *   <li>Degraded → ReadOnly</li>
 *   <li>ReadOnly → Suspended</li>
 *   <li>Degraded → Active  (renewal)</li>
 *   <li>ReadOnly → Active  (renewal)</li>
 * </ul>
 *
 * <p>Suspended is terminal — no further transitions are allowed.</p>
 *
 * <p>The integer values match the {@code PAP_DECAY_*} constants in {@code pap.h}
 * and must never be renumbered.</p>
 */
public enum DecayState {
    /** Full scope, within TTL. */
    ACTIVE(0),
    /** Reduced scope, TTL within decay window, renewal pending. */
    DEGRADED(1),
    /** TTL expired, no execution, observation only. */
    READ_ONLY(2),
    /** Terminal: no activity, awaiting principal review. */
    SUSPENDED(3);

    public final int value;

    DecayState(int value) {
        this.value = value;
    }

    public static DecayState fromInt(int v) {
        for (DecayState s : values()) {
            if (s.value == v) return s;
        }
        throw new IllegalArgumentException("Unknown decay state integer: " + v);
    }
}
