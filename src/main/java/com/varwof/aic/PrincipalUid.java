package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Structured ASN.1 principal identity (draft §5.2 / Go {@code types.PrincipalUid}).
 *
 * <p>DER: {@code SEQUENCE { INTEGER version (DEFAULT 1), UTF8String realm,
 * UTF8String identifier, OCTET STRING keyHash,
 * [0] EXPLICIT AlgorithmIdentifier hashAlgo OPTIONAL }}.
 * A {@code null} {@code hashAlgo} means "absent" and defaults to SHA-256.
 *
 * <p>Communication format: {@code {realm}:{identifier}:{keyFingerprint}} where the
 * fingerprint is {@code base64url(raw, no pad)} of {@code keyHash}.
 */
public final class PrincipalUid {
    public final int version;
    public final String realm;
    public final String identifier;
    public final byte[] keyHash;
    public final AlgorithmIdentifier hashAlgo;

    public PrincipalUid(int version, String realm, String identifier, byte[] keyHash, AlgorithmIdentifier hashAlgo) {
        this.version = version;
        this.realm = Objects.requireNonNull(realm, "realm");
        this.identifier = Objects.requireNonNull(identifier, "identifier");
        this.keyHash = Objects.requireNonNull(keyHash, "keyHash").clone();
        this.hashAlgo = hashAlgo;
    }

    public PrincipalUid(String realm, String identifier, byte[] keyHash, AlgorithmIdentifier hashAlgo) {
        this(1, realm, identifier, keyHash, hashAlgo);
    }

    /** Effective hash algorithm OID (absent defaults to SHA-256). */
    public ASN1ObjectIdentifier hashAlgoOid() {
        if (hashAlgo == null || hashAlgo.oid == null) {
            return Oids.SHA256;
        }
        return hashAlgo.oid;
    }

    /** Communication format {@code {realm}:{identifier}:{keyFingerprint}}. */
    public String displayString() {
        String fp = Base64.getUrlEncoder().withoutPadding().encodeToString(keyHash);
        return realm + ":" + identifier + ":" + fp;
    }

    public byte[] encode() {
        ASN1Encodable[] base = new ASN1Encodable[]{
                Der.integer(version),
                Der.utf8(realm),
                Der.utf8(identifier),
                new DEROctetString(keyHash)};
        ASN1Encodable[] elems = hashAlgo == null
                ? base
                : Arrays.copyOf(base, base.length + 1);
        if (hashAlgo != null) {
            // hashAlgo is encoded as [0] EXPLICIT wrapping the AlgorithmIdentifier SEQUENCE.
            elems[base.length] = Der.explicit(0, asn1Of(hashAlgo.encode()));
        }
        return Der.der(Der.derSequence(elems));
    }

    private static ASN1Primitive asn1Of(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("PrincipalUid: bad hashAlgo DER", ex);
        }
    }

    public static PrincipalUid decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 4 || seq.size() > 5) {
            throw new AicException("PrincipalUid: expected 4-5 elements, got " + seq.size());
        }
        int version = Der.intValue(seq.getObjectAt(0));
        String realm = Der.stringValue(seq.getObjectAt(1));
        String identifier = Der.stringValue(seq.getObjectAt(2));
        byte[] keyHash = Der.octetValue(seq.getObjectAt(3));
        AlgorithmIdentifier hashAlgo = null;
        if (seq.size() == 5) {
            ASN1Primitive inner = Der.optionalTagContent(seq.getObjectAt(4), 0);
            if (inner == null) {
                throw new AicException("PrincipalUid: fifth element must be [0] EXPLICIT AlgorithmIdentifier");
            }
            hashAlgo = AlgorithmIdentifier.decode(inner);
        }
        return new PrincipalUid(version, realm, identifier, keyHash, hashAlgo);
    }

    public static PrincipalUid parse(byte[] derBytes) {
        return decode(asn1Of(derBytes));
    }

    /**
     * Parse from communication format {@code {realm}:{identifier}:{keyFingerprint}},
     * matching Go {@code ParsePrincipalUid}.
     */
    public static PrincipalUid parseDisplayString(String s) {
        String[] parts = s.split(":", 3);
        if (parts.length != 3) {
            throw new AicException("principal_uid: invalid format, expected {realm}:{identifier}:{keyFingerprint}");
        }
        if (parts[0].length() < 1 || parts[0].length() > 128) {
            throw new AicException("principal_uid: realm length " + parts[0].length() + ": must be 1-128");
        }
        if (parts[1].length() < 1 || parts[1].length() > 256) {
            throw new AicException("principal_uid: identifier length " + parts[1].length() + ": must be 1-256");
        }
        byte[] keyHash;
        try {
            keyHash = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException ex) {
            throw new AicException("principal_uid: invalid keyFingerprint base64url: " + ex.getMessage());
        }
        if (keyHash.length < 1 || keyHash.length > 64) {
            throw new AicException("principal_uid: keyHash length " + keyHash.length + ": must be 1-64");
        }
        if (parts[0].contains(":") || parts[1].contains(":")) {
            throw new AicException("principal_uid: realm and identifier must not contain ':'");
        }
        return new PrincipalUid(1, parts[0], parts[1], keyHash, new AlgorithmIdentifier(Oids.SHA256));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PrincipalUid that)) {
            return false;
        }
        return version == that.version
                && realm.equals(that.realm)
                && identifier.equals(that.identifier)
                && Arrays.equals(keyHash, that.keyHash)
                && Objects.equals(hashAlgo, that.hashAlgo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, realm, identifier, hashAlgo) * 31 + Arrays.hashCode(keyHash);
    }

    @Override
    public String toString() {
        return displayString();
    }
}