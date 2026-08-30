package com.varwof.aic;

import java.net.URI;
import java.util.Objects;

/**
 * SPIFFE identity helpers (optional integration, port of Go
 * {@code types/aic.go} SPIFFE functions).
 */
public final class Spiffe {
    private Spiffe() {
    }

    public static final String SCHEME = "spiffe";

    public static String buildId(String trustDomain, String agentName) {
        return "spiffe://" + trustDomain + "/agent/" + agentName;
    }

    public static void validate(String id, String trustDomain) {
        String prefix = "spiffe://" + trustDomain + "/agent/";
        if (id == null || !id.startsWith(prefix)) {
            throw new AicException("spiffe: invalid ID \"" + id + "\": must start with " + prefix);
        }
        String name = id.substring(prefix.length());
        if (name.isEmpty()) {
            throw new AicException("spiffe: invalid ID \"" + id + "\": agent name is empty");
        }
        if (name.contains("/")) {
            throw new AicException("spiffe: invalid ID \"" + id + "\": agent name must not contain /");
        }
    }

    /** First SPIFFE URI in a certificate's SANs, or null. */
    public static String extractFromCert(java.security.cert.X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            java.util.Collection<java.util.List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }
            for (java.util.List<?> entry : sans) {
                if (entry.size() == 2 && ((Number) entry.get(0)).intValue() == 6) {
                    URI uri = URI.create((String) entry.get(1));
                    if (SCHEME.equals(uri.getScheme())) {
                        return uri.toString();
                    }
                }
            }
        } catch (Exception ignore) {
            return null;
        }
        return null;
    }

    public static boolean isAgentId(String agentId) {
        return agentId != null && agentId.startsWith("spiffe://");
    }

    /** "spiffe://varwof.com/agent/scheduler-a" &rarr; "scheduler-a"; identity if not SPIFFE. */
    public static String parseAgentName(String agentId) {
        if (!isAgentId(agentId)) {
            return agentId;
        }
        int idx = agentId.lastIndexOf('/');
        if (idx < 0) {
            return agentId;
        }
        return agentId.substring(idx + 1);
    }

    /** "spiffe://varwof.com/agent/scheduler-a" &rarr; "varwof.com"; "" if not SPIFFE. */
    public static String parseDomain(String agentId) {
        if (!isAgentId(agentId)) {
            return "";
        }
        String trimmed = agentId.substring("spiffe://".length());
        int idx = trimmed.indexOf('/');
        if (idx < 0) {
            return "";
        }
        return trimmed.substring(0, idx);
    }
}