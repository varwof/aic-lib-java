package com.varwof.aic.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.varwof.aic.AicException;

import java.util.ArrayList;
import java.util.List;

/**
 * Capability matching for AIC-JWT (draft-wei-aic-jwt Sections 6.2 and 6.3).
 * Mirrors Go {@code types/aicjwt/capmatch.go}: patterns split into tokens on
 * ':' and '/', '*' matches a single token, '**' crosses separators, and
 * segments may carry {a,b} alternation, [a-z] character classes and embedded
 * '*'.
 */
public final class CapMatch {
    private CapMatch() {
    }

    public static final class Match {
        public final boolean matched;
        public final int score;

        public Match(boolean matched, int score) {
            this.matched = matched;
            this.score = score;
        }
    }

    public static String capPattern(Claims.Capability c) {
        return c.scheme + ":" + c.id;
    }

    /**
     * Matches a target "scheme:id" string against a capability pattern and
     * returns (matched, specificity). Precedence per 07-capability:
     * exact(6) &gt; single-segment(5) &gt; multi-segment(4) &gt; alternation(3)
     * &gt; char class(2) &gt; scheme-level(1).
     */
    public static Match matchPattern(String pattern, String target) {
        String[] ps = pattern.split(":", -1);
        String[] ts = target.split(":", -1);
        if (ps.length == 2 && ps[1].equals("*")) {
            if (ts.length >= 2 && ts[0].equals(ps[0])) {
                return new Match(true, 1);
            }
            return new Match(false, 0);
        }
        if (!matchTokens(tokenize(ps), tokenize(ts))) {
            return new Match(false, 0);
        }
        return new Match(true, patternScore(ps));
    }

    /**
     * Turns ":" and "/" separated segments into a flat token stream that keeps
     * the separators, so '*' matches exactly one literal token and '**'
     * matches across separators.
     */
    static List<String> tokenize(String[] segs) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < segs.length; i++) {
            if (i > 0) {
                out.add(":");
            }
            String s = segs[i];
            if (s.equals("*") || s.equals("**")) {
                out.add(s);
                continue;
            }
            String[] parts = s.split("/", -1);
            for (int j = 0; j < parts.length; j++) {
                if (j > 0) {
                    out.add("/");
                }
                out.add(parts[j]);
            }
        }
        return out;
    }

    static boolean matchTokens(List<String> p, List<String> t) {
        if (p.isEmpty()) {
            return t.isEmpty();
        }
        String head = p.get(0);
        if (head.equals("**")) {
            if (t.isEmpty()) {
                return false;
            }
            for (int i = 1; i <= t.size(); i++) {
                if (matchTokens(p.subList(1, p.size()), t.subList(i, t.size()))) {
                    return true;
                }
            }
            return false;
        }
        if (head.equals("*")) {
            if (t.isEmpty() || t.get(0).equals("/") || t.get(0).equals(":")) {
                return false;
            }
            return matchTokens(p.subList(1, p.size()), t.subList(1, t.size()));
        }
        if (t.isEmpty()) {
            return false;
        }
        if (!matchToken(head, t.get(0))) {
            return false;
        }
        return matchTokens(p.subList(1, p.size()), t.subList(1, t.size()));
    }

    /**
     * Matches a single token against a segment pattern that may carry '*',
     * '{a,b}' alternation and [a-z] character classes.
     */
    static boolean matchToken(String pattern, String target) {
        return matchTokenAt(pattern, 0, target, 0);
    }

    private static boolean matchTokenAt(String p, int pi, String t, int ti) {
        while (true) {
            if (pi >= p.length()) {
                return ti >= t.length();
            }
            char c = p.charAt(pi);
            if (c == '*') {
                for (int k = ti; k <= t.length(); k++) {
                    if (matchTokenAt(p, pi + 1, t, k)) {
                        return true;
                    }
                }
                return false;
            }
            if (c == '{') {
                int end = p.indexOf('}', pi + 1);
                if (end < 0) {
                    return false;
                }
                for (String alt : p.substring(pi + 1, end).split(",", -1)) {
                    if (ti + alt.length() <= t.length()
                            && t.regionMatches(ti, alt, 0, alt.length())
                            && matchTokenAt(p, end + 1, t, ti + alt.length())) {
                        return true;
                    }
                }
                return false;
            }
            if (c == '[') {
                int end = p.indexOf(']', pi + 1);
                if (end < 0 || ti >= t.length()) {
                    return false;
                }
                if (!inCharClass(p.substring(pi + 1, end), t.charAt(ti))) {
                    return false;
                }
                pi = end + 1;
                ti = ti + 1;
                continue;
            }
            if (ti >= t.length() || t.charAt(ti) != c) {
                return false;
            }
            pi = pi + 1;
            ti = ti + 1;
        }
    }

    private static boolean inCharClass(String body, char ch) {
        for (int i = 0; i < body.length(); i++) {
            if (i + 2 < body.length() && body.charAt(i + 1) == '-') {
                if (body.charAt(i) <= ch && ch <= body.charAt(i + 2)) {
                    return true;
                }
                i += 2;
                continue;
            }
            if (body.charAt(i) == ch) {
                return true;
            }
        }
        return false;
    }

    /** Ranks a matched pattern's specificity (07-capability precedence). */
    static int patternScore(String[] ps) {
        if (ps.length == 2 && ps[1].equals("*")) {
            return 1;
        }
        boolean hasDouble = false, hasStar = false, hasAlt = false, hasClass = false;
        for (String s : ps) {
            if (s.contains("**")) {
                hasDouble = true;
            }
            if (s.contains("*")) {
                hasStar = true;
            }
            if (s.contains("{")) {
                hasAlt = true;
            }
            if (s.contains("[")) {
                hasClass = true;
            }
        }
        if (hasDouble) {
            return 4;
        }
        if (hasStar) {
            return 5;
        }
        if (hasAlt) {
            return 3;
        }
        if (hasClass) {
            return 2;
        }
        return 6;
    }

    /**
     * Evaluates a request capability against the allowed capabilities using
     * the glob rules and precedence of draft Section 6.2. The highest-
     * precedence matching rule decides; no match denies.
     */
    public static boolean matchCapabilities(List<Claims.Capability> allowed, Claims.Capability req) {
        String target = capPattern(req);
        int best = 0;
        for (Claims.Capability c : allowed) {
            Match m = matchPattern(capPattern(c), target);
            if (m.matched && m.score > best) {
                best = m.score;
            }
        }
        return best > 0;
    }

    /**
     * Reports whether agent params stay within the grant's parameter bounds:
     * agent numbers must be &lt;= grant numbers, other values equal, arrays
     * subsets. Absent grants trivially bound.
     */
    public static boolean paramsWithinGrant(JsonNode grant, JsonNode agent) {
        if (isEmpty(grant) || isEmpty(agent)) {
            return true;
        }
        return JwtJson.paramsWithin(grant, agent);
    }

    private static boolean isEmpty(JsonNode n) {
        return n == null || n.isNull();
    }

    /**
     * Reports whether an agent capability is a capability-level and
     * parameter-level subset of the principal grants (draft Section 8.2).
     */
    public static boolean capabilitySubset(Claims.Capability agent, List<Claims.Capability> grants) {
        String target = capPattern(agent);
        int best = 0;
        for (Claims.Capability g : grants) {
            Match m = matchPattern(capPattern(g), target);
            if (!m.matched || m.score <= best) {
                continue;
            }
            if (!paramsWithinGrant(g.params, agent.params)) {
                continue;
            }
            best = m.score;
        }
        return best > 0;
    }
}