package com.varwof.aic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Thin JSON helpers shared by the core and JWT packages (Jackson-backed).
 */
public final class JsonUtil {
    private JsonUtil() {
    }

    public static final ObjectMapper MAPPER = new ObjectMapper();

    public static boolean isValidJson(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return false;
        }
        try {
            MAPPER.readTree(raw);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public static JsonNode parse(byte[] raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception ex) {
            throw new AicException("json: invalid JSON: " + ex.getMessage());
        }
    }

    public static JsonNode parse(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception ex) {
            throw new AicException("json: invalid JSON: " + ex.getMessage());
        }
    }

    public static ObjectNode objectNode() {
        return MAPPER.createObjectNode();
    }

    /**
     * True when the JSON document contains a duplicated member name at any
     * nesting level (RFC 8725 &sect;3.2; the Go validator rejects such tokens).
     */
    public static boolean hasDuplicateMemberNames(JsonNode node) {
        if (node == null) {
            return false;
        }
        return walkDuplicates(node);
    }

    private static boolean walkDuplicates(JsonNode node) {
        if (node.isObject()) {
            java.util.Set<String> seen = new java.util.HashSet<>();
            java.util.Iterator<String> names = node.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                if (!seen.add(name)) {
                    return true;
                }
            }
            for (JsonNode child : node) {
                if (walkDuplicates(child)) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                if (walkDuplicates(child)) {
                    return true;
                }
            }
        }
        return false;
    }
}