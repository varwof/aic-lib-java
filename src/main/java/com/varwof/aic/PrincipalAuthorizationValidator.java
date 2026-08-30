package com.varwof.aic;

import java.util.List;
import java.util.Set;

/**
 * Validation of {@link PrincipalAuthorization} (port of Go
 * {@code ValidatePrincipalAuthorization}). Grants must be within limits and
 * constraints must use a recognized constraint scheme.
 */
public final class PrincipalAuthorizationValidator {
    private PrincipalAuthorizationValidator() {
    }

    private static final Set<String> CONSTRAINT_SCHEMES = Set.of("constraint", "constraint-v1", "varwof/constraint-v1");

    public static void validate(PrincipalAuthorization pa) {
        if (pa == null) {
            return;
        }
        if (pa.grants().size() > Limits.MAX_GRANT_ENTRIES) {
            throw new AicException("principal_authorization: grants count " + pa.grants().size()
                    + " exceeds max " + Limits.MAX_GRANT_ENTRIES);
        }
        List<Capability> grants = pa.grants();
        for (int i = 0; i < grants.size(); i++) {
            Capability g = grants.get(i);
            checkLen("principal_authorization: grant[" + i + "].schemeId", g.schemeId(), 1, 128);
            checkLen("principal_authorization: grant[" + i + "].capabilityId", g.capabilityId(), 1, 256);
            if (g.hasParameters() && g.parameters().length > Limits.MAX_CAP_PARAMS) {
                throw new AicException("principal_authorization: grant[" + i + "].parameters length "
                        + g.parameters().length + ": must be 0-" + Limits.MAX_CAP_PARAMS);
            }
        }
        if (pa.authorizationConstraints().size() > Limits.MAX_AUTHORIZATION_CONSTRAINTS) {
            throw new AicException("principal_authorization: authorizationConstraints count "
                    + pa.authorizationConstraints().size() + " exceeds max " + Limits.MAX_AUTHORIZATION_CONSTRAINTS);
        }
        List<Capability> constraints = pa.authorizationConstraints();
        for (int i = 0; i < constraints.size(); i++) {
            Capability c = constraints.get(i);
            if (!CONSTRAINT_SCHEMES.contains(c.schemeId())) {
                throw new AicException("principal_authorization: authorizationConstraints[" + i + "].schemeId \""
                        + c.schemeId() + "\": must be \"constraint\", \"constraint-v1\", or \"varwof/constraint-v1\"");
            }
            if (c.capabilityId().isEmpty()) {
                throw new AicException("principal_authorization: authorizationConstraints[" + i + "].capabilityId: must not be empty");
            }
            if (c.hasParameters() && c.parameters().length > Limits.MAX_CONSTRAINT_PARAMS) {
                throw new AicException("principal_authorization: authorizationConstraints[" + i + "].parameters length "
                        + c.parameters().length + ": must be 0-" + Limits.MAX_CONSTRAINT_PARAMS);
            }
        }
        if (pa.delegationPolicy() != null) {
            int mode = pa.delegationPolicy().allowedMode();
            if (mode < 0 || mode > 1) {
                throw new AicException("principal_authorization: delegationPolicy.allowedMode " + mode + ": must be 0-1");
            }
            int agents = pa.delegationPolicy().maxAgents();
            if (agents < 0 || agents > 255) {
                throw new AicException("principal_authorization: delegationPolicy.maxAgents " + agents + ": must be 0-255");
            }
        }
    }

    private static void checkLen(String what, String s, int min, int max) {
        if (s == null || s.length() < min || s.length() > max) {
            throw new AicException(what + " length " + (s == null ? 0 : s.length()) + ": must be " + min + "-" + max);
        }
    }
}