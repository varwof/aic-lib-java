package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Validation of {@link Aic} and its sub-structures. Port of Go
 * {@code ValidateAIC}, {@code ValidatePrincipalUidKeyHash}, and
 * {@code ValidateMaxConcurrentParam}; rejects the same inputs.
 */
public final class AicValidator {
    private AicValidator() {
    }

    private static final String CONSTRAINT_SCHEME = "varwof/constraint-v1";
    private static final Set<String> CONSTRAINT_SCHEMES = Set.of("constraint", "constraint-v1", CONSTRAINT_SCHEME);

    private static final List<ASN1ObjectIdentifier> KNOWN_EXTENSION_OIDS = List.of(
            Oids.AIC_AGENT_IDENTITY,
            Oids.AIC_DELEGATION_AUTHORIZATION,
            Oids.PRINCIPAL_AUTHORIZATION,
            Oids.MARKET_ACCESS_ID);

    public static void validate(Aic aic) {
        if (aic == null) {
            throw new AicException("aic: nil");
        }
        if (aic.agentId().length() < 1 || aic.agentId().length() > 256) {
            throw new AicException("aic: agentId length " + aic.agentId().length() + ": must be 1-256");
        }
        List<Capability> caps = aic.capabilities();
        if (caps.size() > Limits.MAX_CAPABILITIES) {
            throw new AicException("aic: capabilities count " + caps.size() + " exceeds max " + Limits.MAX_CAPABILITIES);
        }
        for (int i = 0; i < caps.size(); i++) {
            Capability cap = caps.get(i);
            checkLen("aic: capability[" + i + "].schemeId", cap.schemeId(), 1, 128);
            checkLen("aic: capability[" + i + "].capabilityId", cap.capabilityId(), 1, 256);
            if (cap.hasParameters() && cap.parameters().length > Limits.MAX_CAP_PARAMS) {
                throw new AicException("aic: capability[" + i + "].parameters length " + cap.parameters().length
                        + ": must be 0-" + Limits.MAX_CAP_PARAMS);
            }
            if (CONSTRAINT_SCHEME.equals(cap.schemeId())) {
                throw new AicException("aic: capability[" + i + "].schemeId \"" + CONSTRAINT_SCHEME
                        + "\": constraint scheme forbidden in capabilities");
            }
        }
        if (aic.extensions().size() > Limits.MAX_EXTENSIONS_SLOTS) {
            throw new AicException("aic: extensions count " + aic.extensions().size()
                    + " exceeds max " + Limits.MAX_EXTENSIONS_SLOTS);
        }
        for (int i = 0; i < aic.extensions().size(); i++) {
            ExtField ext = aic.extensions().get(i);
            if (ext.critical() && !KNOWN_EXTENSION_OIDS.contains(ext.extnId())) {
                throw new AicException("aic: extensions[" + i + "] has unknown critical OID " + ext.extnId().getId());
            }
        }
        PrincipalUid pu = aic.principalUid();
        checkLen("aic: principalUid.realm", pu.realm, 1, 128);
        checkLen("aic: principalUid.identifier", pu.identifier, 1, 256);
        validatePrincipalUidKeyHash(pu);

        DelegationAuthorization da = aic.delegationAuthorization();
        if (da == null || !da.isPresent()) {
            throw new AicException("aic: delegationAuthorization is required but missing");
        }
        if (da.reason().reasonCode().isEmpty()) {
            throw new AicException("aic: delegationAuth.reason.reasonCode: must not be empty");
        }
        if (da.reason().description().isEmpty()) {
            throw new AicException("aic: delegationAuth.reason.description: must not be empty");
        }
        if (da.reason().reasonCode().length() > 64) {
            throw new AicException("aic: delegationAuth.reason.reasonCode length " + da.reason().reasonCode().length() + ": must be <= 64");
        }
        if (da.reason().description().length() > 512) {
            throw new AicException("aic: delegationAuth.reason.description length " + da.reason().description().length() + ": must be <= 512");
        }
        if (da.nonce() == null || da.nonce().length != Limits.MAX_NONCE_LEN) {
            throw new AicException("aic: delegationAuth.nonce length "
                    + (da.nonce() == null ? 0 : da.nonce().length) + ": must be exactly " + Limits.MAX_NONCE_LEN + " bytes");
        }
        int lifetime = da.requestedLifetime();
        if (lifetime == 0) {
            lifetime = Limits.MIN_REQUESTED_LIFETIME;
        }
        if (lifetime < 1 || lifetime > Limits.MAX_REQUESTED_LIFETIME) {
            throw new AicException("aic: delegationAuth.requestedLifetime " + da.requestedLifetime()
                    + ": must be 1-" + Limits.MAX_REQUESTED_LIFETIME);
        }
        validateConstraints("aic", aic.authorizationConstraints());
    }

    private static void validateConstraints(String prefix, List<Capability> constraints) {
        if (constraints.size() > Limits.MAX_AUTHORIZATION_CONSTRAINTS) {
            throw new AicException(prefix + ": authorizationConstraints count " + constraints.size()
                    + " exceeds max " + Limits.MAX_AUTHORIZATION_CONSTRAINTS);
        }
        for (int i = 0; i < constraints.size(); i++) {
            Capability c = constraints.get(i);
            if (!CONSTRAINT_SCHEMES.contains(c.schemeId())) {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].schemeId \"" + c.schemeId()
                        + "\": must be \"constraint\", \"constraint-v1\", or \"varwof/constraint-v1\"");
            }
            if (c.capabilityId().isEmpty()) {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].capabilityId: must not be empty");
            }
            if (c.hasParameters() && c.parameters().length > Limits.MAX_CONSTRAINT_PARAMS) {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].parameters length "
                        + c.parameters().length + ": must be 0-" + Limits.MAX_CONSTRAINT_PARAMS);
            }
            if (c.hasParameters() && !JsonUtil.isValidJson(c.parameters())) {
                throw new AicException(prefix + ": authorizationConstraints[" + i + "].parameters: invalid JSON");
            }
            if ("max-concurrent".equals(c.capabilityId()) && c.hasParameters()) {
                try {
                    validateMaxConcurrentParam(c.parameters());
                } catch (AicException ex) {
                    throw new AicException(prefix + ": authorizationConstraints[" + i + "]: " + ex.getMessage());
                }
            }
        }
    }

    /** keyHash length must equal the declared hashAlgo output length (default SHA-256 = 32). */
    public static void validatePrincipalUidKeyHash(PrincipalUid pu) {
        if (pu == null || pu.keyHash.length == 0) {
            throw new AicException("aic: principalUid.keyHash: required");
        }
        ASN1ObjectIdentifier algo = pu.hashAlgoOid();
        String name = HashAlgorithms.nameForOid(algo);
        if (name.isEmpty()) {
            throw new AicException("aic: principalUid.hashAlgo " + algo.getId() + ": unsupported keyHash algorithm");
        }
        Integer want = HashAlgorithms.outputLength(algo);
        if (want == null) {
            throw new AicException("aic: principalUid.hashAlgo " + algo.getId() + ": no output length mapping (requires external dependency)");
        }
        if (pu.keyHash.length != want) {
            throw new AicException("aic: principalUid.keyHash length " + pu.keyHash.length
                    + ": must be " + want + " (" + name + ")");
        }
    }

    /** {"max": N} with N in 1..1024; empty input is "not configured" (valid). */
    public static void validateMaxConcurrentParam(byte[] raw) {
        int start = 0;
        int end = raw.length;
        while (start < end && isSpace(raw[start])) {
            start++;
        }
        while (end > start && isSpace(raw[end - 1])) {
            end--;
        }
        if (end - start == 0) {
            return;
        }
        try {
            com.fasterxml.jackson.databind.JsonNode node = JsonUtil.MAPPER.reader().readTree(raw, start, end - start);
            if (!node.isObject() || node.size() != 1 || node.get("max") == null || !node.get("max").canConvertToInt()) {
                throw new AicException("max-concurrent: must be JSON object {\"max\": N}");
            }
            int max = node.get("max").asInt();
            if (max < 1 || max > 1024) {
                throw new AicException("max-concurrent: max " + max + ": must be 1-1024");
            }
        } catch (AicException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AicException("max-concurrent: invalid JSON: " + ex.getMessage());
        }
    }

    private static boolean isSpace(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    private static void checkLen(String what, String s, int min, int max) {
        if (s == null || s.length() < min || s.length() > max) {
            throw new AicException(what + " length " + (s == null ? 0 : s.length()) + ": must be " + min + "-" + max);
        }
    }
}