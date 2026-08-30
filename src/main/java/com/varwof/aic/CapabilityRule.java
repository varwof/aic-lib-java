package com.varwof.aic;

import java.util.Objects;

/**
 * A matching rule with an action (Go {@code types.CapabilityRule}), used for
 * "deny overrides allow" decisions.
 */
public record CapabilityRule(String pattern, boolean deny) {

    public CapabilityRule {
        Objects.requireNonNull(pattern, "pattern");
    }

    public static CapabilityRule allow(String pattern) {
        return new CapabilityRule(pattern, false);
    }

    public static CapabilityRule deny(String pattern) {
        return new CapabilityRule(pattern, true);
    }
}