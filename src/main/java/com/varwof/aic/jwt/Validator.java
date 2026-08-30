package com.varwof.aic.jwt;

import com.varwof.aic.AicException;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * AIC-JWT validation pipeline (draft-wei-aic-jwt Section 11).
 * Mirrors Go {@code types/aicjwt/validate.go} step for step, including the
 * error-prefixed diagnostics used for conformance testing.
 */
public final class Validator {
    private Validator() {
    }

    public static final String TYP_OUTER = "aic+jwt";
    public static final String TYP_DA = "aic+da+jwt";
    public static final String TYP_PA = "aic+pa+jwt";
    public static final String MODE_AUTHORIZED = "authorized";
    public static final String MODE_REPRESENTATIVE = "representative";
    public static final String CONSTRAINT_SCHEME = "varwof/constraint-v1";
    public static final int MAX_LIFETIME = 86400;
    public static final String ALLOWED_MODE_REPRESENTATIVE = "representative_allowed";
    /** Hard upper bound on serialized token size (bound CPU/memory cost). */
    public static final int MAX_TOKEN_SIZE = 64 * 1024;
    /** Maximum serialized size of a capability params object. */
    public static final int MAX_PARAMS_SIZE = 512;

    /** Evaluates a request capability for a scheme (fail-closed for unknown schemes). */
    @FunctionalInterface
    public interface CapabilityPlugin {
        void evaluate(Claims.Capability req, Constraints.RequestContext ctx);
    }

    /** Validates a Token Status List reference. */
    @FunctionalInterface
    public interface StatusChecker {
        void check(Claims.StatusRef ref);
    }

    /** Configures the validation pipeline. */
    public static final class VerifyOptions {
        public Instant now;
        public String expectedIssuer;
        public List<String> expectedAudience;
        public Map<String, PublicKey> issuerKeys;         // kid -> issuer public key
        public KeyHash.PrincipalKeyMaterial principalMaterial; // optional credential bundle
        public Map<String, PublicKey> principalJwks;      // kid -> principal public key (online)
        public PublicKey presenterKey;                    // optional cnf proof-of-possession
        public Claims.Capability requestCapability;       // capability required by this request
        public Constraints.RequestContext requestContext;
        public boolean constraintStrict;
        public Map<String, CapabilityPlugin> capabilityPlugins;
        public StatusChecker statusChecker;
        public NonceStore.Store nonceStore;
        public boolean rejectDepthGt1;
        public boolean requireJtiNonceMatch;
        public Claims.PaClaims pa;                        // optional PrincipalAuthorization material

        public VerifyOptions withDefaults() {
            if (now == null) {
                now = Instant.now();
            }
            return this;
        }
    }

    /** Outcome of the validation pipeline. */
    public static final class Decision {
        public final boolean permit;
        public final String actor;
        public final String principal;
        public final List<Claims.Capability> capabilities;
        public final List<String> notes;

        public Decision(boolean permit, String actor, String principal,
                        List<Claims.Capability> capabilities, List<String> notes) {
            this.permit = permit;
            this.actor = actor;
            this.principal = principal;
            this.capabilities = capabilities;
            this.notes = notes;
        }
    }

    /** Executes the 11-step pipeline of draft Section 11. */
    public static Decision validate(String token, VerifyOptions opts) {
        opts = opts.withDefaults();

        // ---- Step 0: size bound ----
        if (token.length() > MAX_TOKEN_SIZE) {
            throw new AicException("step0: token size " + token.length() + " exceeds max " + MAX_TOKEN_SIZE);
        }

        // ---- Step 1: parse + verify the outer JWS ----
        byte[][] parts;
        try {
            parts = Jws.parseCompact(token);
        } catch (AicException ex) {
            throw new AicException("step1: " + ex.getMessage());
        }
        byte[] hb = parts[0];
        byte[] pb = parts[1];
        if (JwtJson.hasDuplicateKeys(hb)) {
            throw new AicException("step1: outer header contains duplicate JSON member names");
        }
        if (JwtJson.hasDuplicateKeys(pb)) {
            throw new AicException("step1: outer payload contains duplicate JSON member names");
        }
        Claims.Header hdr;
        try {
            hdr = parseHeader(hb);
        } catch (AicException ex) {
            throw new AicException("step1: outer header malformed: " + ex.getMessage());
        }
        // ---- Step 2: header checks ----
        checkHeader(hdr, TYP_OUTER);
        PublicKey issuerKey = opts.issuerKeys == null ? null : opts.issuerKeys.get(hdr.kid);
        if (issuerKey == null) {
            throw new AicException("step2: unknown issuer kid \"" + hdr.kid + "\"");
        }
        try {
            Jws.verifyCompact(token, hdr.alg, issuerKey);
        } catch (AicException ex) {
            throw new AicException("step1: outer signature invalid: " + ex.getMessage());
        }

        // ---- Step 1 (cont.): parse payload only after the signature verifies ----
        // Matches Go, which defers json.Unmarshal(pb, &outer) until after VerifyCompact.
        Claims.OuterClaims outer;
        try {
            outer = parseOuter(pb);
        } catch (AicException ex) {
            throw new AicException("step1: outer payload malformed: " + ex.getMessage());
        }
        if (outer == null) {
            throw new AicException("step1: outer payload malformed");
        }
        checkOuterRequired(outer);

        // ---- Step 3: time checks ----
        try {
            checkTime(outer, opts.now);
        } catch (AicException ex) {
            throw new AicException("step3: " + ex.getMessage());
        }

        // ---- Step 4: DA validation ----
        Claims.DaClaims da = null;
        if (outer.da != null && !outer.da.isEmpty()) {
            try {
                da = validateDa(outer, opts);
            } catch (AicException ex) {
                throw new AicException("step4: " + ex.getMessage());
            }
        } else if (MODE_REPRESENTATIVE.equals(outer.aic.delegationMode)) {
            throw new AicException("step4: representative mode requires a DA JWT");
        } else if (outer.exp - outer.iat > MAX_LIFETIME) {
            throw new AicException("step3: lightweight profile lifetime " + (outer.exp - outer.iat)
                    + " exceeds max " + MAX_LIFETIME);
        }

        // ---- Step 5: consistency checks ----
        if (da != null) {
            try {
                checkConsistency(outer, da);
            } catch (AicException ex) {
                throw new AicException("step5: " + ex.getMessage());
            }
        }

        // ---- Step 6: PA check (representative) ----
        if (MODE_REPRESENTATIVE.equals(outer.aic.delegationMode)) {
            try {
                checkPa(outer, opts);
            } catch (AicException ex) {
                throw new AicException("step6: " + ex.getMessage());
            }
        }

        // ---- Step 7: constraint evaluation ----
        List<String> notes;
        try {
            notes = Constraints.evaluateConstraints(
                    outer.aic.constraints, opts.requestContext, opts.constraintStrict);
        } catch (AicException ex) {
            throw new AicException("step7: aic.constraints: " + ex.getMessage());
        }

        // ---- Step 8: delegation depth check ----
        try {
            checkDepth(outer.aic, opts);
        } catch (AicException ex) {
            throw new AicException("step8: " + ex.getMessage());
        }

        // ---- Step 9: capability evaluation ----
        if (opts.requestCapability != null) {
            if (!CapMatch.matchCapabilities(outer.aic.capabilities, opts.requestCapability)) {
                throw new AicException("step9: capability " + opts.requestCapability.scheme + ":"
                        + opts.requestCapability.id + " not allowed by aic.capabilities");
            }
            CapabilityPlugin plugin = opts.capabilityPlugins == null ? null
                    : opts.capabilityPlugins.get(opts.requestCapability.scheme);
            if (plugin == null) {
                throw new AicException("step9: unknown capability scheme \""
                        + opts.requestCapability.scheme + "\" (fail-closed)");
            }
            try {
                plugin.evaluate(opts.requestCapability, opts.requestContext);
            } catch (AicException ex) {
                throw new AicException("step9: scheme plugin denies " + opts.requestCapability.scheme + ":"
                        + opts.requestCapability.id + ": " + ex.getMessage());
            }
        }

        // ---- Step 10: status check ----
        if (outer.status != null) {
            if (opts.statusChecker == null) {
                throw new AicException("step10: status claim present but no status checker configured");
            }
            try {
                opts.statusChecker.check(outer.status);
            } catch (AicException ex) {
                throw new AicException("step10: token status check failed: " + ex.getMessage());
            }
        }

        // ---- issuer / audience / presenter binding ----
        if (opts.expectedIssuer != null && !opts.expectedIssuer.isEmpty()
                && !opts.expectedIssuer.equals(outer.iss)) {
            throw new AicException("iss \"" + outer.iss + "\" does not match expected issuer \""
                    + opts.expectedIssuer + "\"");
        }
        if (opts.expectedAudience != null && !opts.expectedAudience.isEmpty()) {
            boolean matched = false;
            for (String a : opts.expectedAudience) {
                if (outer.aud.contains(a)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                throw new AicException("aud " + outer.aud + " does not include any of "
                        + opts.expectedAudience + " (audience confusion)");
            }
        }
        if (opts.presenterKey != null) {
            if (outer.cnf == null || outer.cnf.jkt == null || outer.cnf.jkt.isEmpty()) {
                throw new AicException("cnf claim required but missing");
            }
            String thumb = KeyHash.keyHashOf(opts.presenterKey, "jkt");
            if (!thumb.equals(outer.cnf.jkt)) {
                throw new AicException("cnf: presenter key does not match token cnf.jkt (token theft)");
            }
        }

        // ---- Decision ----
        String actor = outer.sub;
        if (MODE_REPRESENTATIVE.equals(outer.aic.delegationMode)) {
            actor = outer.aic.principal.id;
        }
        return new Decision(true, actor, outer.aic.principal.id, outer.aic.capabilities, notes);
    }

    /** Validates a JOSE header against the expected typ and algorithm allowlist. */
    public static void checkHeader(Claims.Header h, String expectedTyp) {
        if (!expectedTyp.equals(h.typ)) {
            throw new AicException("unexpected typ \"" + h.typ + "\" (expected \"" + expectedTyp + "\")");
        }
        if (h.alg == null || h.alg.isEmpty() || "none".equals(h.alg)) {
            throw new AicException("alg missing or none");
        }
        if (!Jws.ALLOWED_ALGS.contains(h.alg)) {
            throw new AicException("alg \"" + h.alg + "\" not in allowlist");
        }
        if (h.kid == null || h.kid.isEmpty()) {
            throw new AicException("kid required");
        }
        if (h.crit != null) {
            for (String c : h.crit) {
                throw new AicException("unsupported critical header \"" + c + "\"");
            }
        }
    }

    private static void checkOuterRequired(Claims.OuterClaims o) {
        if (o.iss == null || o.iss.isEmpty()) {
            throw new AicException("iss required");
        }
        if (o.sub == null || o.sub.isEmpty() || o.sub.length() > 256) {
            throw new AicException("sub (agentId) required, 1..256 chars");
        }
        if (o.aud == null || o.aud.size() == 0) {
            throw new AicException("aud required");
        }
        if (o.iat == 0 || o.exp == 0 || o.exp <= o.iat) {
            throw new AicException("iat/exp required and exp must be after iat");
        }
        if (o.jti == null || o.jti.isEmpty()) {
            throw new AicException("jti required");
        }
        if (o.cnf == null || o.cnf.jkt == null || o.cnf.jkt.isEmpty()) {
            throw new AicException("cnf required");
        }
        if (o.aic == null) {
            throw new AicException("aic claim required");
        }
        if (o.aic.ver != 1) {
            throw new AicException("aic.ver must be 1");
        }
        Claims.Principal p = o.aic.principal;
        if (p == null || p.realm == null || p.realm.isEmpty() || p.realm.length() > 128
                || p.id == null || p.id.isEmpty() || p.id.length() > 256
                || p.keyHash == null || p.keyHash.isEmpty()) {
            throw new AicException("aic.principal realm/id/key_hash required within size limits");
        }
        String alg = p.hashAlg;
        if (alg == null || alg.isEmpty()) {
            alg = "sha-256";
        }
        if (!KeyHash.SUPPORTED_HASH_ALGS.containsKey(alg)) {
            throw new AicException("unsupported aic.principal.hash_alg \"" + p.hashAlg + "\"");
        }
        if (!MODE_AUTHORIZED.equals(o.aic.delegationMode) && !MODE_REPRESENTATIVE.equals(o.aic.delegationMode)) {
            throw new AicException("aic.delegation_mode must be \"" + MODE_AUTHORIZED
                    + "\" or \"" + MODE_REPRESENTATIVE + "\"");
        }
        if (o.aic.capabilities == null || o.aic.capabilities.size() < 1 || o.aic.capabilities.size() > 256) {
            throw new AicException("aic.capabilities must contain 1..256 entries");
        }
        for (Claims.Capability c : o.aic.capabilities) {
            if (JwtJson.compactLength(c.params) > MAX_PARAMS_SIZE) {
                throw new AicException("aic.capabilities params exceed " + MAX_PARAMS_SIZE + " bytes");
            }
        }
        if (o.aic.constraints != null && o.aic.constraints.size() > 32) {
            throw new AicException("aic.constraints must not exceed 32 entries");
        }
        if (o.aic.constraints != null) {
            for (Claims.Capability c : o.aic.constraints) {
                if (JwtJson.compactLength(c.params) > MAX_PARAMS_SIZE) {
                    throw new AicException("aic.constraints params exceed " + MAX_PARAMS_SIZE + " bytes");
                }
            }
        }
        if (o.aic.extensions != null && o.aic.extensions.size() > 32) {
            throw new AicException("aic.extensions must not exceed 32 entries");
        }
    }

    private static void checkTime(Claims.OuterClaims o, Instant now) {
        long nowUnix = now.getEpochSecond();
        if (o.nbf != null && nowUnix < o.nbf) {
            throw new AicException("token not yet valid (nbf)");
        }
        if (nowUnix > o.exp) {
            throw new AicException("token expired");
        }
    }

    private static void checkDaRequired(Claims.DaClaims d) {
        if (d.ver != 1) {
            throw new AicException("DA ver must be 1");
        }
        if (d.agentId == null || d.agentId.isEmpty() || d.agentId.length() > 256) {
            throw new AicException("DA agent_id required, 1..256 chars");
        }
        if (d.principal == null || d.principal.realm == null || d.principal.realm.isEmpty()
                || d.principal.id == null || d.principal.id.isEmpty()
                || d.principal.keyHash == null || d.principal.keyHash.isEmpty()) {
            throw new AicException("DA principal required");
        }
        if (d.reason == null || d.reason.code == null || d.reason.code.isEmpty()
                || d.reason.desc == null || d.reason.desc.isEmpty()) {
            throw new AicException("DA reason.code and reason.desc required");
        }
        if (d.capabilities == null || d.capabilities.size() < 1 || d.capabilities.size() > 256) {
            throw new AicException("DA capabilities must contain 1..256 entries");
        }
        for (Claims.Capability c : d.capabilities) {
            if (JwtJson.compactLength(c.params) > MAX_PARAMS_SIZE) {
                throw new AicException("DA capabilities params exceed " + MAX_PARAMS_SIZE + " bytes");
            }
        }
        if (!MODE_AUTHORIZED.equals(d.delegationMode) && !MODE_REPRESENTATIVE.equals(d.delegationMode)) {
            throw new AicException("DA delegation_mode invalid");
        }
        if (d.constraints != null && d.constraints.size() > 32) {
            throw new AicException("DA constraints must not exceed 32 entries");
        }
        if (d.constraints != null) {
            for (Claims.Capability c : d.constraints) {
                if (JwtJson.compactLength(c.params) > MAX_PARAMS_SIZE) {
                    throw new AicException("DA constraints params exceed " + MAX_PARAMS_SIZE + " bytes");
                }
            }
        }
        if (d.requestedLifetime < 1 || d.requestedLifetime > MAX_LIFETIME) {
            throw new AicException("DA requested_lifetime must be in 1.." + MAX_LIFETIME);
        }
        if (d.ts == 0) {
            throw new AicException("DA ts required");
        }
        if (d.nonce == null || d.nonce.isEmpty()) {
            throw new AicException("DA nonce required");
        }
    }

    /** Validates a DA JWT in isolation: header, claims, signature, binding, nonce. */
    public static Claims.DaClaims validateDa(String daToken, VerifyOptions opts) {
        if (daToken.length() > MAX_TOKEN_SIZE) {
            throw new AicException("DA token size " + daToken.length() + " exceeds max " + MAX_TOKEN_SIZE);
        }
        byte[][] parts;
        try {
            parts = Jws.parseCompact(daToken);
        } catch (AicException ex) {
            throw new AicException("DA parse: " + ex.getMessage());
        }
        if (JwtJson.hasDuplicateKeys(parts[0])) {
            throw new AicException("DA header contains duplicate JSON member names");
        }
        if (JwtJson.hasDuplicateKeys(parts[1])) {
            throw new AicException("DA payload contains duplicate JSON member names");
        }
        Claims.Header hdr;
        try {
            hdr = parseHeader(parts[0]);
        } catch (AicException ex) {
            throw new AicException("DA header malformed: " + ex.getMessage());
        }
        checkHeader(hdr, TYP_DA);
        Claims.DaClaims da;
        try {
            da = JwtJson.MAPPER.readValue(parts[1], Claims.DaClaims.class);
        } catch (Exception ex) {
            throw new AicException("DA payload malformed: " + ex.getMessage());
        }
        checkDaRequired(da);
        PublicKey pub = resolvePrincipalKey(da.principal, hdr.kid, opts);
        try {
            Jws.verifyCompact(daToken, hdr.alg, pub);
        } catch (AicException ex) {
            throw new AicException("DA signature invalid: " + ex.getMessage());
        }
        String alg = da.principal.hashAlg;
        if (alg == null || alg.isEmpty()) {
            alg = "sha-256";
        }
        String binding;
        try {
            binding = KeyHash.keyHashOf(pub, alg);
        } catch (AicException ex) {
            throw new AicException(ex.getMessage());
        }
        if (!binding.equals(da.principal.keyHash)) {
            throw new AicException("DA principal key_hash mismatch");
        }
        byte[] nonceBytes;
        try {
            nonceBytes = Jws.b64uDecode(da.nonce);
        } catch (AicException ex) {
            nonceBytes = null;
        }
        if (nonceBytes == null || nonceBytes.length != 32) {
            throw new AicException("DA nonce must be the base64url of 32 bytes");
        }
        if (opts.nonceStore != null) {
            try {
                opts.nonceStore.checkAndAdd(da.nonce);
            } catch (NonceStore.NonceReuseException ex) {
                throw new AicException("DA nonce reuse: " + ex.getMessage());
            }
        }
        return da;
    }

    private static Claims.DaClaims validateDa(Claims.OuterClaims outer, VerifyOptions opts) {
        Claims.DaClaims da = validateDa(outer.da, opts);
        if (opts.requireJtiNonceMatch && !outer.jti.equals(da.nonce)) {
            throw new AicException("outer jti does not match DA nonce");
        }
        if (outer.exp - outer.iat > da.requestedLifetime) {
            throw new AicException("token lifetime " + (outer.exp - outer.iat)
                    + " exceeds DA requested_lifetime " + da.requestedLifetime);
        }
        return da;
    }

    private static PublicKey resolvePrincipalKey(Claims.Principal p, String kid, VerifyOptions opts) {
        if (opts.principalMaterial != null) {
            if (kid != null && !kid.isEmpty() && opts.principalMaterial.jwk != null) {
                KeyHash.Jwk j = opts.principalMaterial.jwk.get(kid);
                if (j != null) {
                    try {
                        return KeyHash.jwkToPublic(j);
                    } catch (AicException ex) {
                        // fall through to binding lookup
                    }
                }
            }
            try {
                return opts.principalMaterial.lookupByBinding(p);
            } catch (AicException ex) {
                // fall through to online JWKS
            }
        }
        if (opts.principalJwks != null && kid != null && !kid.isEmpty()) {
            PublicKey pub = opts.principalJwks.get(kid);
            if (pub != null) {
                return pub;
            }
        }
        throw new AicException("principal key not resolvable (kid \"" + kid + "\")");
    }

    private static void checkConsistency(Claims.OuterClaims o, Claims.DaClaims da) {
        if (!da.agentId.equals(o.sub)) {
            throw new AicException("DA agent_id \"" + da.agentId + "\" != outer sub \"" + o.sub + "\"");
        }
        if (!JwtJson.jsonEqual(da.principal, o.aic.principal)) {
            throw new AicException("DA principal != outer aic.principal");
        }
        if (!da.delegationMode.equals(o.aic.delegationMode)) {
            throw new AicException("DA delegation_mode != outer aic.delegation_mode");
        }
        if (!JwtJson.jsonEqual(da.capabilities, o.aic.capabilities)) {
            throw new AicException("DA capabilities != outer aic.capabilities");
        }
        if (!JwtJson.jsonEqual(da.constraints, o.aic.constraints)) {
            throw new AicException("DA constraints != outer aic.constraints");
        }
    }

    private static void checkPa(Claims.OuterClaims o, VerifyOptions opts) {
        Claims.PaClaims pa = opts.pa;
        if (pa == null) {
            throw new AicException("representative mode requires PrincipalAuthorization material");
        }
        if (pa.ver != 1) {
            throw new AicException("PA ver must be 1");
        }
        if (!JwtJson.jsonEqual(pa.principal, o.aic.principal)) {
            throw new AicException("PA principal != outer aic.principal");
        }
        if (pa.delegationPolicy == null || !ALLOWED_MODE_REPRESENTATIVE.equals(pa.delegationPolicy.allowedMode)) {
            throw new AicException("delegation policy does not allow representative mode");
        }
        for (Claims.Capability c : o.aic.capabilities) {
            if (!CapMatch.capabilitySubset(c, pa.grants)) {
                throw new AicException("capability " + c.scheme + ":" + c.id + " not within P_grants");
            }
        }
        if (pa.grants != null) {
            for (Claims.Capability g : pa.grants) {
                if (JwtJson.compactLength(g.params) > MAX_PARAMS_SIZE) {
                    throw new AicException("PA grants params exceed " + MAX_PARAMS_SIZE + " bytes");
                }
            }
        }
        if (pa.constraints != null) {
            for (Claims.Capability c : pa.constraints) {
                if (JwtJson.compactLength(c.params) > MAX_PARAMS_SIZE) {
                    throw new AicException("PA constraints params exceed " + MAX_PARAMS_SIZE + " bytes");
                }
            }
        }
        Constraints.evaluateConstraints(pa.constraints, opts.requestContext, opts.constraintStrict);
    }

    private static void checkDepth(Claims.AicClaims a, VerifyOptions opts) {
        int chainDepth = a.chainDepth == null ? 0 : a.chainDepth;
        int maxDepth = a.maxDepth == null ? 0 : a.maxDepth;
        if (chainDepth < 0 || chainDepth > 255) {
            throw new AicException("chain_depth out of range");
        }
        if (maxDepth < 0 || maxDepth > 255) {
            throw new AicException("max_depth out of range");
        }
        if (chainDepth > maxDepth) {
            throw new AicException("chain_depth " + chainDepth + " exceeds max_depth " + maxDepth);
        }
        if (opts.rejectDepthGt1 && maxDepth > 1) {
            throw new AicException("max_depth " + maxDepth + " exceeds recommended limit 1");
        }
    }

    private static Claims.Header parseHeader(byte[] raw) {
        try {
            return JwtJson.MAPPER.readValue(raw, Claims.Header.class);
        } catch (Exception ex) {
            throw new AicException(ex.getMessage());
        }
    }

    private static Claims.OuterClaims parseOuter(byte[] raw) {
        try {
            return JwtJson.MAPPER.readValue(raw, Claims.OuterClaims.class);
        } catch (Exception ex) {
            throw new AicException(ex.getMessage());
        }
    }
}