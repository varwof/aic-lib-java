package com.varwof.aic.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.varwof.aic.AicException;
import com.varwof.aic.Cidr;

import java.net.InetAddress;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Constraint evaluation for AIC-JWT (draft-wei-aic-jwt Section 7).
 * Mirrors Go {@code types/aicjwt/constraints.go}.
 */
public final class Constraints {
    private Constraints() {
    }

    /** Deployment-side inputs for constraint evaluation and capability plugins. */
    public static final class RequestContext {
        public Instant now;
        public InetAddress sourceIp;
        public int concurrentCount;

        public RequestContext() {
        }

        public RequestContext(Instant now, InetAddress sourceIp, int concurrentCount) {
            this.now = now;
            this.sourceIp = sourceIp;
            this.concurrentCount = concurrentCount;
        }
    }

    /** Evaluates one constraint capability. */
    @FunctionalInterface
    public interface ConstraintEvaluator {
        void evaluate(Claims.Capability capability, RequestContext ctx);
    }

    /** Built-in constraint types of draft Section 7. */
    public static final Map<String, ConstraintEvaluator> BUILTIN_CONSTRAINT_IDS = new LinkedHashMap<>();

    static {
        BUILTIN_CONSTRAINT_IDS.put("allowed-cidr", Constraints::evalAllowedCidr);
        BUILTIN_CONSTRAINT_IDS.put("max-concurrent", Constraints::evalMaxConcurrent);
        BUILTIN_CONSTRAINT_IDS.put("time-window", Constraints::evalTimeWindow);
    }

    static void evalAllowedCidr(Claims.Capability c, RequestContext ctx) {
        if (c.params == null || !c.params.isArray()) {
            throw new AicException("allowed-cidr: params must be a JSON array of CIDR strings");
        }
        if (ctx.sourceIp == null) {
            throw new AicException("allowed-cidr: no source IP in request context");
        }
        for (JsonNode n : c.params) {
            if (!n.isTextual()) {
                throw new AicException("allowed-cidr: params must be a JSON array of CIDR strings");
            }
            try {
                if (Cidr.parse(n.textValue()).contains(ctx.sourceIp)) {
                    return;
                }
            } catch (AicException ex) {
                throw new AicException("allowed-cidr: invalid CIDR \"" + n.textValue() + "\"");
            }
        }
        throw new AicException("allowed-cidr: source IP " + ctx.sourceIp.getHostAddress() + " not in allowed ranges");
    }

    static void evalMaxConcurrent(Claims.Capability c, RequestContext ctx) {
        if (c.params == null || !c.params.isObject() || !c.params.path("max").isNumber()) {
            throw new AicException("max-concurrent: params must be {\"max\": N}");
        }
        int max = c.params.path("max").asInt();
        if (max < 1) {
            throw new AicException("max-concurrent: max must be >= 1");
        }
        if (ctx.concurrentCount >= max) {
            throw new AicException("max-concurrent: concurrent count " + ctx.concurrentCount
                    + " exceeds max " + max);
        }
    }

    static void evalTimeWindow(Claims.Capability c, RequestContext ctx) {
        if (c.params == null || !c.params.isObject()
                || !c.params.path("start").isTextual() || !c.params.path("end").isTextual()) {
            throw new AicException("time-window: params must be {\"start\":...,\"end\":...}");
        }
        String startS = c.params.path("start").textValue();
        String endS = c.params.path("end").textValue();
        int start = parseHm(startS);
        int end = parseHm(endS);
        Instant now = ctx.now == null ? Instant.now() : ctx.now;
        ZonedDateTime z = now.atZone(ZoneOffset.UTC);
        int cur = z.getHour() * 60 + z.getMinute();
        if (start <= end) {
            if (cur < start || cur > end) {
                throw new AicException("time-window: now " + String.format("%02d:%02d", z.getHour(), z.getMinute())
                        + " outside [" + startS + "," + endS + "]");
            }
        } else if (cur < start && cur > end) {
            throw new AicException("time-window: now " + String.format("%02d:%02d", z.getHour(), z.getMinute())
                    + " outside overnight window [" + startS + "," + endS + "]");
        }
    }

    private static int parseHm(String s) {
        String[] parts = s.split(":", 2);
        if (parts.length != 2) {
            throw new AicException("time-window: invalid HH:MM \"" + s + "\"");
        }
        try {
            int h = Integer.parseInt(parts[0]);
            int m = Integer.parseInt(parts[1]);
            if (h < 0 || h > 23 || m < 0 || m > 59) {
                throw new AicException("time-window: invalid HH:MM \"" + s + "\"");
            }
            return h * 60 + m;
        } catch (NumberFormatException ex) {
            throw new AicException("time-window: invalid HH:MM \"" + s + "\"");
        }
    }

    /**
     * Evaluates all constraints with AND semantics. Unknown constraint types
     * are ignored with an audit note unless strict is true; schemes other than
     * varwof/constraint-v1 are rejected.
     */
    public static List<String> evaluateConstraints(List<Claims.Capability> cs, RequestContext ctx, boolean strict) {
        List<String> notes = new ArrayList<>();
        if (cs == null) {
            return notes;
        }
        for (Claims.Capability c : cs) {
            if (!"varwof/constraint-v1".equals(c.scheme)) {
                throw new AicException("constraint scheme \"" + c.scheme
                        + "\" not allowed (must be varwof/constraint-v1)");
            }
            ConstraintEvaluator eval = BUILTIN_CONSTRAINT_IDS.get(c.id);
            if (eval == null) {
                if (strict) {
                    throw new AicException("unknown constraint type \"" + c.id + "\" (strict mode)");
                }
                notes.add("audit: unknown constraint type \"" + c.id + "\" ignored");
                continue;
            }
            eval.evaluate(c, ctx);
        }
        return notes;
    }
}