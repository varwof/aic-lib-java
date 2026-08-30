package com.varwof.aic;

/**
 * Priority levels for capabilityId matching (Go {@code types/match_priority.go}).
 * Higher values are more specific; the highest-priority matching rule wins,
 * and at equal priority deny overrides allow.
 */
public final class MatchPriority {
    private MatchPriority() {
    }

    public static final int NO_MATCH = 0;
    public static final int GLOBAL = 1;
    public static final int SCHEME = 2;
    public static final int MULTI = 3;
    public static final int SINGLE = 4;
    public static final int EXACT = 5;

    public static String name(int p) {
        return switch (p) {
            case NO_MATCH -> "no-match";
            case GLOBAL -> "global";
            case SCHEME -> "scheme";
            case MULTI -> "multi";
            case SINGLE -> "single";
            case EXACT -> "exact";
            default -> "unknown(" + p + ")";
        };
    }

    /** Semantic ordering for deny-overrides-allow decisions: higher beats lower. */
    public static int rank(int p) {
        return p;
    }
}