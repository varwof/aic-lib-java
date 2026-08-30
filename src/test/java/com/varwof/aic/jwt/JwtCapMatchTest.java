package com.varwof.aic.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ports Go {@code types/aicjwt/capmatch_test.go} (CapabilitySubset) plus the
 * pattern/precedence rules of draft Section 6.2.
 */
class JwtCapMatchTest {

    private static Claims.Capability cap(String scheme, String id) {
        return new Claims.Capability(scheme, id, null);
    }

    private static Claims.Capability cap(String scheme, String id, String paramsJson) {
        return new Claims.Capability(scheme, id, JwtJson.parse(paramsJson));
    }

    @Test
    void capabilitySubset() {
        List<Claims.Capability> queryStar = List.of(cap("database", "query:*"));
        List<Claims.Capability> querySelect = List.of(cap("database", "query:SELECT"));

        assertTrue(CapMatch.capabilitySubset(cap("database", "query:SELECT"), querySelect)); // exact
        assertTrue(CapMatch.capabilitySubset(cap("database", "query:SELECT"), queryStar)); // wildcard grant
        assertFalse(CapMatch.capabilitySubset(cap("database", "query:*"), querySelect)); // specific grant
        assertFalse(CapMatch.capabilitySubset(cap("database", "query:SELECT"),
                List.of(cap("http", "query:*")))); // scheme mismatch
        assertTrue(CapMatch.capabilitySubset(cap("database", "query:SELECT", "{\"max_rows\":500}"),
                List.of(cap("database", "query:*", "{\"max_rows\":1000}")))); // within bound
        assertFalse(CapMatch.capabilitySubset(cap("database", "query:SELECT", "{\"max_rows\":2000}"),
                List.of(cap("database", "query:*", "{\"max_rows\":1000}")))); // exceeds bound
        assertTrue(CapMatch.capabilitySubset(cap("database", "query:SELECT", "{\"max_rows\":100}"),
                List.of(cap("database", "query:*")))); // grant unrestricted
        assertFalse(CapMatch.capabilitySubset(cap("database", "query:SELECT"), List.of())); // no grants
    }

    @Test
    void patternPrecedence() {
        // scheme-level wildcard beats nothing but loses to everything specific
        assertTrue(CapMatch.matchPattern("database:*", "database:query").matched);
        assertEquals(1, CapMatch.matchPattern("database:*", "database:query").score);
        assertFalse(CapMatch.matchPattern("database:*", "https:query").matched);

        // exact > single-segment * > multi-segment **
        assertEquals(6, CapMatch.matchPattern("a:b/c", "a:b/c").score);
        assertEquals(5, CapMatch.matchPattern("a:*/who", "a:b/who").score);
        assertEquals(4, CapMatch.matchPattern("a:b/**", "a:b/c/d/who").score);
        assertEquals(5, CapMatch.matchPattern("database:query:S*", "database:query:SELECT").score);

        // one "*" matches a single character, one ":"-segment or path segment,
        // never a separator
        assertTrue(CapMatch.matchPattern("a:S*e", "a:Some").matched);
        assertTrue(CapMatch.matchPattern("a:*:c", "a:b:c").matched);
        assertFalse(CapMatch.matchPattern("http:{GET,POST}:*", "http:GET:/v1/users").matched);

        // "**" crosses ':' and '/'
        assertTrue(CapMatch.matchPattern("a:**", "a:x:y").matched);
        assertTrue(CapMatch.matchPattern("a:**", "a:x/y:z").matched);
        assertTrue(CapMatch.matchPattern("a:**", "a:b").matched);
        assertEquals(4, CapMatch.matchPattern("a:**", "a:x/y:z").score);

        // alternation and char-class tokens (star present -> score 5)
        assertTrue(CapMatch.matchPattern("http:{GET,POST}:*", "http:GET:id").matched);
        assertEquals(5, CapMatch.matchPattern("http:{GET,POST}:*", "http:GET:id").score);
        assertTrue(CapMatch.matchPattern("http:[A-Z]*:*", "http:GET:id").matched);
        assertEquals(5, CapMatch.matchPattern("http:[A-Z]*:*", "http:GET:id").score);

        // alternation alone ranks below any star
        assertTrue(CapMatch.matchPattern("http:{GET,POST}", "http:GET").matched);
        assertEquals(3, CapMatch.matchPattern("http:{GET,POST}", "http:GET").score);

        // "**" requires at least one token
        assertFalse(CapMatch.matchPattern("a:**", "a").matched);
    }

    @Test
    void paramsWithinBounds() {
        JsonNode grant = JwtJson.parse("{\"max_rows\":1000,\"readonly\":true,\"tables\":[\"users\"],\"limit\":10.5}");
        assertTrue(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"max_rows\":500}")));
        assertFalse(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"max_rows\":2000}")));
        assertFalse(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"readonly\":false}")));
        assertTrue(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"tables\":[\"users\"]}")));
        assertFalse(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"tables\":[\"admins\"]}")));
        assertTrue(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"limit\":10.0}")));
        assertFalse(CapMatch.paramsWithinGrant(grant, JwtJson.parse("{\"limit\":11}")));
        // absent grant (unrestricted) trivially bounds any agent
        assertTrue(CapMatch.paramsWithinGrant(null, JwtJson.parse("{\"max_rows\":999999}")));
    }
}