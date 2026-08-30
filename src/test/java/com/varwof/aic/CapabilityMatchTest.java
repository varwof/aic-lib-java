package com.varwof.aic;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Capability matching. Vector-for-vector port of Go
 * {@code match_priority_test.go} and {@code matchcap_test.go}.
 */
class CapabilityMatchTest {

    @Test
    void matchCapabilityPriorityLevels() {
        Object[][] cases = {
                // exact
                {"database:query:SELECT", "database:query:SELECT", MatchPriority.EXACT},
                // single-segment wildcard
                {"database:query:SELECT", "database:query:*", MatchPriority.SINGLE},
                {"database:query:SELECT", "database:*:SELECT", MatchPriority.SINGLE},
                {"database:query:EXPLAIN", "database:*:SELECT", MatchPriority.NO_MATCH},
                // multi-segment wildcard
                {"database:query:SELECT", "database:**", MatchPriority.MULTI},
                {"database:query:SELECT", "**", MatchPriority.GLOBAL},
                {"database:query:SELECT", "database:**:SELECT", MatchPriority.MULTI},
                {"database:query:EXPLAIN", "database:**:SELECT", MatchPriority.NO_MATCH},
                // scheme wildcard
                {"mysql:query:SELECT", "*:query:SELECT", MatchPriority.SCHEME},
                {"pgsql:query:SELECT", "*:query:SELECT", MatchPriority.SCHEME},
                {"mysql:query:EXPLAIN", "*:query:SELECT", MatchPriority.NO_MATCH},
                // global wildcard
                {"anything:at:all", "*", MatchPriority.GLOBAL},
                {"anything:at:all", "**", MatchPriority.GLOBAL},
                {"anything:at:all", "*:*", MatchPriority.GLOBAL},
        };
        for (Object[] c : cases) {
            String id = (String) c[0];
            String pat = (String) c[1];
            int want = (Integer) c[2];
            assertEquals(CapabilityMatcher.matchCapabilityPriority(id, pat), want,
                    () -> "MatchCapabilityPriority(" + id + ", " + pat + ")");
        }
    }

    @Test
    void exactBeatsGlobalDeny() {
        String id = "database:query:SELECT";
        List<CapabilityRule> rules = List.of(
                new CapabilityRule("**", true),
                new CapabilityRule("database:query:*", true),
                new CapabilityRule("database:query:SELECT", false));
        CapabilityRuleMatch m = CapabilityMatcher.matchCapabilityRules(id, rules);
        assertTrue(m.matched);
        assertFalse(m.deny);
        assertEquals(MatchPriority.EXACT, m.priority);
        assertEquals("database:query:SELECT", m.pattern);
    }

    @Test
    void denyOverridesAllowAtSamePriority() {
        String id = "database:query:SELECT";
        List<CapabilityRule> rules = List.of(
                new CapabilityRule("database:**", true),
                new CapabilityRule("database:query:SELECT", false));
        CapabilityRuleMatch m = CapabilityMatcher.matchCapabilityRules(id, rules);
        assertTrue(m.matched);
        assertFalse(m.deny, "exact allow should beat multi deny");

        List<CapabilityRule> rules2 = List.of(
                new CapabilityRule("database:query:SELECT", false),
                new CapabilityRule("database:query:SELECT", true));
        CapabilityRuleMatch m2 = CapabilityMatcher.matchCapabilityRules(id, rules2);
        assertTrue(m2.matched);
        assertTrue(m2.deny);
    }

    @Test
    void noMatchWhenNoRuleMatches() {
        CapabilityRuleMatch m = CapabilityMatcher.matchCapabilityRules("ca:create",
                List.of(new CapabilityRule("crl:*", false)));
        assertFalse(m.matched);
    }

    @Test
    void matchCapabilityCompatibility() {
        String[][] compat = {
                {"gateway:admin", "gateway:admin"},
                {"gateway:admin", "gateway:*"},
                {"ca:issuing:create", "ca:**"},
                {"anything", "**"},
                {"anything", "*"},
        };
        for (String[] c : compat) {
            assertTrue(() -> CapabilityMatcher.matchCapability(c[0], c[1]),
                    () -> "MatchCapability(" + c[0] + "," + c[1] + ") should be true");
            assertTrue(() -> CapabilityMatcher.matchCapabilityPriority(c[0], c[1]) > MatchPriority.NO_MATCH,
                    () -> "priority should match for " + c[0] + "," + c[1]);
        }
        assertFalse(CapabilityMatcher.matchCapability("ca:create", "crl:*"));
    }

    @Test
    void matchCapabilityExact() {
        assertTrue(CapabilityMatcher.matchCapability("gateway:admin", "gateway:admin"));
        assertTrue(CapabilityMatcher.matchCapability("anything", "**"));
        assertTrue(CapabilityMatcher.matchCapability("anything", "*"));
        assertTrue(CapabilityMatcher.matchCapability("ca:list", "ca:*"));
        assertTrue(CapabilityMatcher.matchCapability("ca:create", "ca:*"));
        assertTrue(CapabilityMatcher.matchCapability("gateway:admin", "gateway:?dmin"));
        assertTrue(CapabilityMatcher.matchCapability("ca:issuing:create", "ca:**"));
        assertFalse(CapabilityMatcher.matchCapability("ca:create", "crl:*"));
        assertFalse(CapabilityMatcher.matchCapability("gateway:admin", "gateway:ops"));
    }

    @Test
    void matchDoubleStarSemantics() {
        assertTrue(CapabilityMatcher.matchCapability("ca:issuing:create", "ca:**"));
        assertTrue(CapabilityMatcher.matchCapability("a/b:c", "a/**"));
        assertFalse(CapabilityMatcher.matchCapability("ca:create", "crl:**"));
    }
}