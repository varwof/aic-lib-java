package com.varwof.aic;

/**
 * How an agent may be delegated. Mirrors {@code types/delegation_mode.go}.
 */
public enum DelegationMode {
    /** delegated directly by the principal or by chain, without representation calls. */
    AUTHORIZED(0),
    /** the agent may act as a representative and exercise the principal's identity. */
    REPRESENTATIVE(1);

    public final int value;

    DelegationMode(int value) {
        this.value = value;
    }

    public boolean isRepresentative() {
        return this == REPRESENTATIVE;
    }

    public static DelegationMode fromValue(int v) {
        return switch (v) {
            case 0 -> AUTHORIZED;
            case 1 -> REPRESENTATIVE;
            default -> throw new AicException("invalid delegation mode: " + v);
        };
    }

    @Override
    public String toString() {
        return isRepresentative() ? "representative" : "authorized";
    }
}