package com.varwof.aic.jwt;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.varwof.aic.AicException;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JSON utilities for the JWT package. Mirrors Go
 * {@code types/aicjwt/jsonutil.go} and the semantic comparisons in
 * {@code claims.go}.
 */
public final class JwtJson {
    private JwtJson() {
    }

    public static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        // the AIC-JWT wire format uses snake_case member names (matching the Go
        // struct tags); map Java camelCase fields transparently
        MAPPER.setPropertyNamingStrategy(com.fasterxml.jackson.databind.PropertyNamingStrategies.SNAKE_CASE);
    }

    /**
     * Reports whether the JSON document contains an object with duplicate
     * member names at any nesting level (RFC 8725). Detected on the raw token
     * stream before claims are interpreted, because a tree parse silently
     * keeps only one of the duplicates.
     */
    public static boolean hasDuplicateKeys(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return false;
        }
        try (JsonParser p = new JsonFactory().createParser(raw)) {
            com.fasterxml.jackson.core.JsonToken tok = p.nextToken();
            if (tok != com.fasterxml.jackson.core.JsonToken.START_OBJECT
                    && tok != com.fasterxml.jackson.core.JsonToken.START_ARRAY) {
                return false;
            }
            return walkDeep(p);
        } catch (IOException ex) {
            return false;
        }
    }

    private static boolean walkDeep(JsonParser p) throws IOException {
        if (p.currentToken() == com.fasterxml.jackson.core.JsonToken.START_OBJECT) {
            Set<String> seen = new HashSet<>();
            while (true) {
                com.fasterxml.jackson.core.JsonToken tok = p.nextToken();
                if (tok == com.fasterxml.jackson.core.JsonToken.END_OBJECT) {
                    return false;
                }
                if (tok != com.fasterxml.jackson.core.JsonToken.FIELD_NAME) {
                    return false;
                }
                String name = p.currentName();
                if (!seen.add(name)) {
                    return true;
                }
                com.fasterxml.jackson.core.JsonToken vt = p.nextToken();
                if (vt == com.fasterxml.jackson.core.JsonToken.START_OBJECT
                        || vt == com.fasterxml.jackson.core.JsonToken.START_ARRAY) {
                    if (walkDeep(p)) {
                        return true;
                    }
                }
            }
        }
        // array
        while (true) {
            com.fasterxml.jackson.core.JsonToken tok = p.nextToken();
            if (tok == com.fasterxml.jackson.core.JsonToken.END_ARRAY) {
                return false;
            }
            if (tok == com.fasterxml.jackson.core.JsonToken.START_OBJECT
                    || tok == com.fasterxml.jackson.core.JsonToken.START_ARRAY) {
                if (walkDeep(p)) {
                    return true;
                }
            }
        }
    }

    public static JsonNode parse(byte[] raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (IOException ex) {
            throw new AicException("json: invalid JSON: " + ex.getMessage());
        }
    }

    public static JsonNode parse(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (IOException ex) {
            throw new AicException("json: invalid JSON: " + ex.getMessage());
        }
    }

    public static JsonNode toNode(Object value) {
        return MAPPER.valueToTree(value);
    }

    /** Compact serialized byte length of a JSON subtree (0 when absent). */
    public static int compactLength(JsonNode node) {
        if (node == null) {
            return 0;
        }
        try {
            return MAPPER.writeValueAsBytes(node).length;
        } catch (Exception ex) {
            throw new AicException("json: cannot serialize: " + ex.getMessage());
        }
    }

    /** Semantic JSON equality (member order and whitespace are ignored). */
    public static boolean jsonEqual(Object a, Object b) {
        JsonNode an = toNode(a);
        JsonNode bn = toNode(b);
        return an.equals(bn);
    }

    /**
     * Numeric-bounded delegate for {@code ParamsWithinGrant}: agent values must
     * stay within grant values (agent &lt;= grant for numbers), non-numeric
     * values must be equal, arrays must be subsets, objects recurse.
     */
    public static boolean paramsWithin(JsonNode grant, JsonNode agent) {
        if (grant.isObject()) {
            if (!agent.isObject()) {
                return false;
            }
            java.util.Iterator<Map.Entry<String, JsonNode>> fields = agent.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> f = fields.next();
                JsonNode gv = grant.get(f.getKey());
                if (gv == null || gv.isNull()) {
                    return false;
                }
                if (!paramsWithin(gv, f.getValue())) {
                    return false;
                }
            }
            return true;
        }
        if (grant.isNumber()) {
            if (!agent.isNumber()) {
                return false;
            }
            return numLte(agent, grant);
        }
        if (grant.isTextual()) {
            return agent.isTextual() && agent.textValue().equals(grant.textValue());
        }
        if (grant.isBoolean()) {
            return agent.isBoolean() && agent.booleanValue() == grant.booleanValue();
        }
        if (grant.isArray()) {
            if (!agent.isArray()) {
                return false;
            }
            for (JsonNode x : agent) {
                boolean found = false;
                for (JsonNode y : grant) {
                    if (x.equals(y)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
            return true;
        }
        return grant.equals(agent);
    }

    private static boolean numLte(JsonNode agent, JsonNode grant) {
        if (agent.isIntegralNumber() && grant.isIntegralNumber()) {
            BigInteger a = new BigDecimal(agent.asText()).toBigInteger();
            BigInteger g = new BigDecimal(grant.asText()).toBigInteger();
            return a.compareTo(g) <= 0;
        }
        return new BigDecimal(agent.asText()).compareTo(new BigDecimal(grant.asText())) <= 0;
    }
}