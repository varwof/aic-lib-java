package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Arrays;
import java.util.Objects;

/**
 * Agent SPKI key binding for DelegationAuthTBS version 2.
 * Port of Go {@code types.AgentKeyBinding}.
 *
 * <p>DER: {@code SEQUENCE { OCTET STRING keyHash,
 * [0] EXPLICIT AlgorithmIdentifier hashAlgo OPTIONAL }}.
 * When hashAlgo is absent, SHA-256 is the default.
 */
public final class AgentKeyBinding {
    public final byte[] keyHash;
    public final AlgorithmIdentifier hashAlgo;

    public AgentKeyBinding(byte[] keyHash, AlgorithmIdentifier hashAlgo) {
        this.keyHash = keyHash == null ? null : keyHash.clone();
        this.hashAlgo = hashAlgo;
    }

    /** Effective hash algorithm OID (absent defaults to SHA-256). */
    public ASN1ObjectIdentifier hashAlgoOid() {
        if (hashAlgo == null || hashAlgo.oid == null) {
            return Oids.SHA256;
        }
        return hashAlgo.oid;
    }

    /** True when keyHash is null or empty (absent binding). */
    public boolean isZero() {
        return keyHash == null || keyHash.length == 0;
    }

    public byte[] encode() {
        ASN1Encodable[] base = new ASN1Encodable[]{
                new DEROctetString(keyHash == null ? new byte[0] : keyHash)};
        ASN1Encodable[] elems = hashAlgo == null
                ? base
                : Arrays.copyOf(base, base.length + 1);
        if (hashAlgo != null) {
            elems[1] = Der.explicit(0, asn1Of(hashAlgo.encode()));
        }
        return Der.der(Der.derSequence(elems));
    }

    private static ASN1Primitive asn1Of(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("AgentKeyBinding: bad nested DER", ex);
        }
    }

    public static AgentKeyBinding decode(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 1 || seq.size() > 2) {
            throw new AicException("AgentKeyBinding: expected 1-2 elements, got " + seq.size());
        }
        byte[] keyHash = Der.octetValue(seq.getObjectAt(0));
        AlgorithmIdentifier hashAlgo = null;
        if (seq.size() == 2) {
            ASN1Primitive inner = Der.optionalTagContent(seq.getObjectAt(1), 0);
            if (inner == null) {
                throw new AicException("AgentKeyBinding: second element must be [0] EXPLICIT AlgorithmIdentifier");
            }
            hashAlgo = AlgorithmIdentifier.decode(inner);
        }
        return new AgentKeyBinding(keyHash, hashAlgo);
    }

    public static AgentKeyBinding parse(byte[] derBytes) {
        try {
            return decode(ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("AgentKeyBinding: bad DER", ex);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AgentKeyBinding that)) {
            return false;
        }
        return Arrays.equals(keyHash, that.keyHash) && Objects.equals(hashAlgo, that.hashAlgo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashAlgo) * 31 + Arrays.hashCode(keyHash);
    }
}
