package com.varwof.aic;

import java.util.List;

/**
 * Capability ID matching (glob) and priority-based rule decisions.
 * Port of Go {@code types/match_priority.go} and the {@code MatchCapability} /
 * {@code matchDoubleStar} helpers in {@code types/aic.go}.
 *
 * <p>IDs and patterns are segmented on {@code ':'}. A segment may then also be
 * globbed on {@code '/'}; {@code *} matches any single segment (or within a
 * segment any char run not crossing {@code '/'}), {@code ?} a single char and
 * {@code **} matches one or more cross-segment parts.
 */
public final class CapabilityMatcher {
    private CapabilityMatcher() {
    }

    // ---- string-level matcher used by AIC.CheckPermission / IntersectPermissions ----

    /**
     * Mirrors Go {@code MatchCapability}: exact, then {@code "**"/"*"}, then
     * path-style glob, then a single {@code **} split.
     */
    public static boolean matchCapability(String id, String pattern) {
        if (id == null || pattern == null) {
            return false;
        }
        if (id.equals(pattern)) {
            return true;
        }
        if (pattern.equals("**") || pattern.equals("*")) {
            return true;
        }
        if (globMatch(pattern, id, '/')) {
            return true;
        }
        if (pattern.contains("**")) {
            return matchDoubleStar(id, pattern);
        }
        return false;
    }

    /**
     * Mirrors Go {@code matchDoubleStar}: splits on {@code **}, trims the
     * trailing/leading {@code "/"} around it, then validates the leftover
     * segments are non-empty and not {@code ".."}.
     */
    static boolean matchDoubleStar(String id, String pattern) {
        String[] parts = pattern.split("\\*\\*", -1);
        if (parts.length != 2) {
            return false;
        }
        String prefix = stripTrailingSlash(parts[0]);
        String suffix = stripLeadingSlash(parts[1]);

        String remaining = id;
        if (!prefix.isEmpty()) {
            if (!remaining.startsWith(prefix)) {
                return false;
            }
            remaining = remaining.substring(prefix.length());
            remaining = stripLeadingSlash(remaining);
        }
        if (!suffix.isEmpty()) {
            if (!remaining.endsWith(suffix)) {
                return false;
            }
            remaining = remaining.substring(0, remaining.length() - suffix.length());
            remaining = stripTrailingSlash(remaining);
        }
        if (remaining.isEmpty()) {
            return true;
        }
        for (String seg : remaining.split("/", -1)) {
            if (seg.isEmpty() || seg.equals("..")) {
                return false;
            }
        }
        return true;
    }

    private static String stripLeadingSlash(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '/') {
            i++;
        }
        return s.substring(i);
    }

    private static String stripTrailingSlash(String s) {
        int i = s.length();
        while (i > 0 && s.charAt(i - 1) == '/') {
            i--;
        }
        return s.substring(0, i);
    }

    // ---- priority matcher (port of match_priority.go) ----

    public static int matchCapabilityPriority(String id, String pattern) {
        if (id == null || pattern == null) {
            return MatchPriority.NO_MATCH;
        }
        if (id.equals(pattern)) {
            return MatchPriority.EXACT;
        }
        if (pattern.equals("*") || pattern.equals("**") || pattern.equals("*:*")) {
            return MatchPriority.GLOBAL;
        }
        String[] idSegs = splitNonEmpty(id);
        String[] patSegs = splitNonEmpty(pattern);
        if (idSegs.length == 0 || patSegs.length == 0) {
            return MatchPriority.NO_MATCH;
        }
        // scheme wildcard: first segment "*", remaining segments exact (no wildcard)
        if (patSegs.length >= 2 && patSegs[0].equals("*") && !segmentsContainWildcard(patSegs, 1)) {
            if (idSegs.length == patSegs.length && segmentsEqual(idSegs, patSegs, 1)) {
                return MatchPriority.SCHEME;
            }
        }
        if (segmentsContainDoubleStar(patSegs)) {
            if (matchDoubleStarSegments(idSegs, patSegs)) {
                return MatchPriority.MULTI;
            }
        }
        if (idSegs.length == patSegs.length && matchSingleSegments(idSegs, patSegs)) {
            return MatchPriority.SINGLE;
        }
        return MatchPriority.NO_MATCH;
    }

    /**
     * Decision over a rule set: the highest-priority matching rule wins; at
     * equal priority deny overrides allow; no match &rarr; {@code matched=false}
     * (caller applies default, typically deny).
     */
    public static CapabilityRuleMatch matchCapabilityRules(String id, List<CapabilityRule> rules) {
        CapabilityRuleMatch best = CapabilityRuleMatch.NO_MATCH;
        for (CapabilityRule r : rules) {
            int p = matchCapabilityPriority(id, r.pattern());
            if (p > best.priority) {
                best = new CapabilityRuleMatch(true, r.deny(), p, r.pattern());
            } else if (p == best.priority && p > 0 && r.deny() && !best.deny) {
                best = new CapabilityRuleMatch(true, true, p, r.pattern());
            }
        }
        return best;
    }

    private static boolean segmentsContainWildcard(String[] segs, int from) {
        for (int i = from; i < segs.length; i++) {
            if (segs[i].indexOf('*') >= 0 || segs[i].indexOf('?') >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean segmentsContainDoubleStar(String[] segs) {
        for (String s : segs) {
            if (s.equals("**")) {
                return true;
            }
        }
        return false;
    }

    private static boolean segmentsEqual(String[] a, String[] b, int from) {
        if (a.length - from != b.length - from) {
            return false;
        }
        for (int i = from; i < a.length; i++) {
            if (!a[i].equals(b[i])) {
                return false;
            }
        }
        return true;
    }

    /** Segment match: literal, {@code *} or intra-segment glob ({@code *}/{@code ?}). */
    private static boolean matchSingleSegment(String idSeg, String patSeg) {
        if (patSeg.equals("*")) {
            return true;
        }
        if (patSeg.indexOf('*') >= 0 || patSeg.indexOf('?') >= 0) {
            return globMatch(patSeg, idSeg, '/');
        }
        return idSeg.equals(patSeg);
    }

    private static boolean matchSingleSegments(String[] idSegs, String[] patSegs) {
        for (int i = 0; i < patSegs.length; i++) {
            if (patSegs[i].equals("**")) {
                return false;
            }
            if (!matchSingleSegment(idSegs[i], patSegs[i])) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchDoubleStarSegments(String[] idSegs, String[] patSegs) {
        int first = -1;
        int last = -1;
        for (int i = 0; i < patSegs.length; i++) {
            if (patSegs[i].equals("**")) {
                if (first == -1) {
                    first = i;
                }
                last = i;
            }
        }
        if (first == -1) {
            return false;
        }
        if (first > idSegs.length) {
            return false;
        }
        for (int i = 0; i < first; i++) {
            if (!matchSingleSegment(idSegs[i], patSegs[i])) {
                return false;
            }
        }
        int suffixLen = patSegs.length - last - 1;
        if (first + suffixLen > idSegs.length) {
            return false;
        }
        for (int i = 0; i < suffixLen; i++) {
            if (!matchSingleSegment(idSegs[idSegs.length - suffixLen + i], patSegs[last + 1 + i])) {
                return false;
            }
        }
        return true;
    }

    private static String[] splitNonEmpty(String s) {
        String[] raw = s.split(":", -1);
        java.util.ArrayList<String> out = new java.util.ArrayList<>(raw.length);
        for (String r : raw) {
            if (!r.isEmpty()) {
                out.add(r);
            }
        }
        return out.toArray(new String[0]);
    }

    // ---- glob primitive (path/filepath.Match semantics, separator '/') ----

    /**
     * Shell glob with {@code * ? [..]} support and separator-sensitivity,
     * ported from Go's {@code path.Match}/{@code filepath.Match} (separator
     * '/'). {@code *} matches any sequence of non-separator characters,
     * {@code ?} any single non-separator character, and {@code [...]} the usual
     * character classes. A malformed pattern (e.g. unterminated class) is a
     * no-match.
     */
    public static boolean globMatch(String pattern, String name, char separator) {
        if (pattern == null || name == null) {
            return false;
        }
        return matchPattern(pattern, name, separator);
    }

    private static boolean matchPattern(String pattern, String name, char separator) {
        // trivial cases
        if (pattern.indexOf('*') < 0 && pattern.indexOf('?') < 0 && pattern.indexOf('[') < 0) {
            return pattern.equals(name);
        }
        // iterate chunks
        ScanResult sr = scanChunk(pattern, separator);
        while (true) {
            boolean star = sr.star;
            String chunk = sr.chunk;
            String rest = sr.rest;
            if (star && chunk.isEmpty()) {
                // trailing '*' matches the rest of the name unless it contains a separator
                return !name.contains(String.valueOf(separator));
            }
            // match chunk at the current position
            MatchResult t = matchChunk(chunk, name, separator);
            if (star) {
                if (t.ok) {
                    String name0 = name;
                    String remainder0 = t.remainder;
                    if (matchRest(rest, remainder0, separator)) {
                        return true;
                    }
                    // also try skipping chars up to the next separator
                    for (int i = 0; i < name0.length() && name0.charAt(i) != separator; i++) {
                        MatchResult t2 = matchChunk(chunk, name0.substring(i + 1), separator);
                        if (t2.ok && matchRest(rest, t2.remainder, separator)) {
                            return true;
                        }
                    }
                    return false;
                }
                // no match at current position: skip over non-separator chars
                for (int i = 0; i < name.length() && name.charAt(i) != separator; i++) {
                    MatchResult t2 = matchChunk(chunk, name.substring(i + 1), separator);
                    if (t2.ok && matchRest(rest, t2.remainder, separator)) {
                        return true;
                    }
                }
                return false;
            }
            if (!t.ok) {
                return false;
            }
            name = t.remainder;
            boolean hasStar = rest.indexOf('*') >= 0 || rest.indexOf('?') >= 0 || rest.indexOf('[') >= 0;
            if (!hasStar) {
                return rest.equals(name);
            }
            sr = scanChunk(rest, separator);
        }
    }

    private static boolean matchRest(String rest, String name, char separator) {
        if (rest.isEmpty()) {
            return name.isEmpty();
        }
        return matchPattern(rest, name, separator);
    }

    private record ScanResult(boolean star, String chunk, String rest) {
    }

    private record MatchResult(boolean ok, String remainder) {
    }

    /** Split the leading chunk from a pattern (Go path.scanChunk). */
    private static ScanResult scanChunk(String pattern, char separator) {
        String star = "";
        if (!pattern.isEmpty() && pattern.charAt(0) == '*') {
            star = "*";
            pattern = pattern.substring(1);
        }
        boolean inrange = false;
        int i = 0;
        for (i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            switch (c) {
                case '\\':
                    if (i + 1 < pattern.length()) {
                        i++; // skip escaped char; kept literally in the chunk
                    }
                    break;
                case '[':
                    inrange = true;
                    break;
                case ']':
                    inrange = false;
                    break;
                case '*':
                    if (!inrange) {
                        return new ScanResult(!star.isEmpty(), pattern.substring(0, i), pattern.substring(i));
                    }
                    break;
                default:
                    break;
            }
        }
        return new ScanResult(!star.isEmpty(), pattern, "");
    }

    /** Match a single chunk (no unescaped '*') against a name prefix (Go matchChunk). */
    private static MatchResult matchChunk(String chunk, String name, char separator) {
        int ci = 0;
        int ni = 0;
        while (ci < chunk.length()) {
            char pc = chunk.charAt(ci);
            if (pc == '?') {
                if (ni >= name.length() || name.charAt(ni) == separator) {
                    return new MatchResult(false, null);
                }
                ci++;
                ni++;
                continue;
            }
            if (pc == '[') {
                if (ni >= name.length() || name.charAt(ni) == separator) {
                    return new MatchResult(false, null);
                }
                int j = ci + 1;
                boolean negate = false;
                if (j < chunk.length() && chunk.charAt(j) == '^') {
                    negate = true;
                    j++;
                } else if (j < chunk.length() && chunk.charAt(j) == '!') {
                    negate = true;
                    j++;
                }
                int close = -1;
                for (int k = j; k < chunk.length(); k++) {
                    if (chunk.charAt(k) == ']') {
                        close = k;
                        break;
                    }
                }
                if (close < 0) {
                    return new MatchResult(false, null); // bad pattern
                }
                char nc = name.charAt(ni);
                boolean matched = false;
                boolean firstChar = true;
                for (int k = j; k < close; k++) {
                    char c = chunk.charAt(k);
                    if (c == '\\') {
                        c = chunk.charAt(++k);
                    }
                    if (!firstChar && k + 1 < close && chunk.charAt(k) == '-' && chunk.charAt(k + 1) != ']') {
                        char hi = chunk.charAt(++k);
                        if (nc >= c && nc <= hi) {
                            matched = true;
                        }
                        firstChar = false;
                        continue;
                    }
                    firstChar = false;
                    if (nc == c) {
                        matched = true;
                    }
                }
                if (matched == negate) {
                    return new MatchResult(false, null);
                }
                ci = close + 1;
                ni++;
                continue;
            }
            if (ni >= name.length() || name.charAt(ni) != pc) {
                return new MatchResult(false, null);
            }
            ci++;
            ni++;
        }
        return new MatchResult(true, name.substring(ni));
    }
}