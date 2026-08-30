package com.varwof.aic;

import java.util.Objects;

/**
 * Result of matching a capability ID against a rule set
 * (Go {@code types.CapabilityRuleMatch}).
 */
public final class CapabilityRuleMatch {
    public final boolean matched;
    public final boolean deny;
    public final int priority;
    public final String pattern;

    public static final CapabilityRuleMatch NO_MATCH = new CapabilityRuleMatch(false, false, MatchPriority.NO_MATCH, "");

    public CapabilityRuleMatch(boolean matched, boolean deny, int priority, String pattern) {
        this.matched = matched;
        this.deny = deny;
        this.priority = priority;
        this.pattern = Objects.requireNonNull(pattern, "pattern");
    }

    @Override
    public String toString() {
        if (!matched) {
            return "no-match";
        }
        return (deny ? "deny(" : "allow(") + pattern + ", " + MatchPriority.name(priority) + ")";
    }
}