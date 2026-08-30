package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;

/**
 * Hash algorithm name &harr; OID &harr; output-length mappings, and SPKI
 * keyHash computation. Port of Go {@code types/hash.go} (SHA-2/SHA-3 family;
 * SM3 OID is recognized for naming but computation is delegated to the caller,
 * mirroring the Go "no external dependency" policy).
 */
public final class HashAlgorithms {
    private HashAlgorithms() {
    }

    private static final Map<String, ASN1ObjectIdentifier> NAME_TO_OID = new LinkedHashMap<>();
    private static final Map<String, Integer> OUTPUT_LEN = new LinkedHashMap<>();

    static {
        NAME_TO_OID.put("sha256", Oids.SHA256);
        NAME_TO_OID.put("sha384", Oids.SHA384);
        NAME_TO_OID.put("sha512", Oids.SHA512);
        NAME_TO_OID.put("sha3-256", Oids.SHA3_256);
        NAME_TO_OID.put("sha3-384", Oids.SHA3_384);
        NAME_TO_OID.put("sha3-512", Oids.SHA3_512);

        OUTPUT_LEN.put("sha256", 32);
        OUTPUT_LEN.put("sha384", 48);
        OUTPUT_LEN.put("sha512", 64);
        OUTPUT_LEN.put("sha3-256", 32);
        OUTPUT_LEN.put("sha3-384", 48);
        OUTPUT_LEN.put("sha3-512", 64);
    }

    public static ASN1ObjectIdentifier oidForName(String name) {
        return NAME_TO_OID.get(name.toLowerCase(Locale.ROOT));
    }

    /** Canonical name for a hash OID; empty string when unknown. */
    public static String nameForOid(ASN1ObjectIdentifier oid) {
        if (oid != null) {
            for (Map.Entry<String, ASN1ObjectIdentifier> e : NAME_TO_OID.entrySet()) {
                if (e.getValue().equals(oid)) {
                    return e.getKey();
                }
            }
        }
        return "";
    }

    public static Integer outputLength(ASN1ObjectIdentifier oid) {
        return OUTPUT_LEN.get(nameForOid(oid));
    }

    /** Parse a name to OID; empty input yields null (like Go's nil for empty). */
    public static ASN1ObjectIdentifier parse(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        ASN1ObjectIdentifier oid = oidForName(s);
        if (oid == null) {
            throw new AicException("hash_algo: unsupported algorithm \"" + s
                    + "\", supported: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512");
        }
        return oid;
    }

    public static ASN1ObjectIdentifier defaultOid() {
        return Oids.SHA256;
    }

    /** SPKI DER digest (keyHash) computed with the given hash OID. */
    public static byte[] keyHashFromSpki(ASN1ObjectIdentifier algo, byte[] spkiDer) {
        String name = nameForOid(algo);
        if (name.isEmpty()) {
            throw new AicException("keyhash: unsupported hashAlgo " + algo + " (requires external dependency)");
        }
        try {
            MessageDigest md = digestFor(name);
            return md.digest(spkiDer);
        } catch (NoSuchAlgorithmException ex) {
            throw new AicException("keyhash: JCA provider missing " + name + ": " + ex.getMessage());
        }
    }

    static MessageDigest digestFor(String name) throws NoSuchAlgorithmException {
        return switch (name) {
            case "sha256" -> MessageDigest.getInstance("SHA-256");
            case "sha384" -> MessageDigest.getInstance("SHA-384");
            case "sha512" -> MessageDigest.getInstance("SHA-512");
            case "sha3-256" -> MessageDigest.getInstance("SHA3-256");
            case "sha3-384" -> MessageDigest.getInstance("SHA3-384");
            case "sha3-512" -> MessageDigest.getInstance("SHA3-512");
            default -> throw new NoSuchAlgorithmException(name);
        };
    }
}