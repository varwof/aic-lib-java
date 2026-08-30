package com.varwof.aic.jwt;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JSON claim models for AIC-JWT tokens (draft-wei-aic-jwt Sections 4 and 5).
 * Mirrors Go {@code types/aicjwt/claims.go}. Serialization omits members that
 * map to Go's {@code omitempty}.
 */
public final class Claims {
    private Claims() {
    }

    /** JOSE protected header shared by all AIC-JWT token types. */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class Header {
        public String alg;
        public String typ;
        public String kid;
        public List<String> crit;
        public KeyHash.Jwk jwk;

        public Header() {
        }

        public Header(String alg, String typ, String kid) {
            this.alg = alg;
            this.typ = typ;
            this.kid = kid;
        }
    }

    /** Audience accepts a JSON string or an array of strings (RFC 9068). */
    public static final class Audience {
        public final List<String> values;

        public Audience(List<String> values) {
            this.values = values == null ? List.of() : List.copyOf(values);
        }

        public Audience(String single) {
            this.values = List.of(single);
        }

        @JsonCreator
        public static Audience from(JsonNode node) throws com.fasterxml.jackson.core.JsonProcessingException {
            if (node.isTextual()) {
                return new Audience(node.textValue());
            }
            if (node.isArray()) {
                List<String> out = new ArrayList<>();
                for (JsonNode n : node) {
                    if (!n.isTextual()) {
                        throw new com.fasterxml.jackson.core.JsonProcessingException(
                                "aud array member is not a string") {
                        };
                    }
                    out.add(n.textValue());
                }
                return new Audience(out);
            }
            throw new com.fasterxml.jackson.core.JsonProcessingException(
                    "aud must be a string or an array of strings") {
            };
        }

        @JsonValue
        public List<String> toJson() {
            return values;
        }

        public boolean contains(String v) {
            return values.contains(v);
        }

        public int size() {
            return values.size();
        }

        public String get(int i) {
            return values.get(i);
        }

        @Override
        public String toString() {
            return values.toString();
        }
    }

    /** RFC 7800 confirmation claim (jkt form). */
    public static class Cnf {
        public String jkt;

        public Cnf() {
        }

        public Cnf(String jkt) {
            this.jkt = jkt;
        }
    }

    /** Token Status List entry reference. */
    public static class StatusRef {
        public int idx;
        public String uri;
    }

    /** Principal is the principalUid equivalent (draft Section 5.1.2). */
    public static class Principal {
        public String realm;
        public String id;
        public String keyHash;
        public String hashAlg;

        public Principal() {
        }

        public Principal(String realm, String id, String keyHash, String hashAlg) {
            this.realm = realm;
            this.id = id;
            this.keyHash = keyHash;
            this.hashAlg = hashAlg;
        }
    }

    /** Capability is the unified container (draft Section 6.1). */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class Capability {
        public String scheme;
        public String id;
        public JsonNode params;

        public Capability() {
        }

        public Capability(String scheme, String id) {
            this.scheme = scheme;
            this.id = id;
        }

        public Capability(String scheme, String id, JsonNode params) {
            this.scheme = scheme;
            this.id = id;
            this.params = params;
        }
    }

    /** Extension mirrors the AIC extensions slot. */
    public static class Extension {
        public boolean critical;
        public JsonNode value;

        public Extension() {
        }

        public Extension(boolean critical, JsonNode value) {
            this.critical = critical;
            this.value = value;
        }
    }

    /** AIC claims (draft Section 5.1.2). */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class AicClaims {
        public int ver;
        public Principal principal;
        public String delegationMode;
        public List<Capability> capabilities;
        public List<Capability> constraints;
        public Integer chainDepth;
        public Integer maxDepth;
        public Map<String, Extension> extensions;

        public AicClaims() {
        }

        public AicClaims(int ver, Principal principal, String delegationMode, List<Capability> capabilities) {
            this.ver = ver;
            this.principal = principal;
            this.delegationMode = delegationMode;
            this.capabilities = capabilities;
        }
    }

    /** Outer AIC-JWT payload (draft Section 5.1). */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class OuterClaims {
        public String iss;
        public String sub;
        public Audience aud;
        public long iat;
        public long exp;
        public Long nbf;
        public String jti;
        public Cnf cnf;
        public String scope;
        public String clientId;
        public StatusRef status;
        public AicClaims aic;
        public String da;
        public JsonNode authorizationDetails;

        public OuterClaims() {
        }
    }

    /** Delegation reason (draft Section 5.2). */
    public static class Reason {
        public String code;
        public String desc;

        public Reason() {
        }

        public Reason(String code, String desc) {
            this.code = code;
            this.desc = desc;
        }
    }

    /** Inner DA JWT payload, the JSON equivalent of DelegationAuthTBS. */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class DaClaims {
        public int ver;
        public String agentId;
        public Principal principal;
        public Reason reason;
        public List<Capability> capabilities;
        public String delegationMode;
        public List<Capability> constraints;
        public int requestedLifetime;
        public long ts;
        public String nonce;

        public DaClaims() {
        }
    }

    /** JSON equivalent of the ASN.1 DelegationPolicy (draft Section 5.3). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class DelegationPolicy {
        public int maxAgents;
        public String allowedMode;
        public Integer maxSessionHours;

        public DelegationPolicy() {
        }

        public DelegationPolicy(int maxAgents, String allowedMode) {
            this.maxAgents = maxAgents;
            this.allowedMode = allowedMode;
        }
    }

    /** PA JWT payload (draft Section 5.3). */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class PaClaims {
        public int ver;
        public Principal principal;
        public List<Capability> grants;
        public List<Capability> constraints;
        public DelegationPolicy delegationPolicy;
        public Map<String, Extension> extensions;

        public PaClaims() {
        }
    }
}