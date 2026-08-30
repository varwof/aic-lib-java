package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.util.Arrays;
import java.util.Objects;

/**
 * X.509-style AlgorithmIdentifier ({@code SEQUENCE { OID [, params] }}).
 *
 * <p>Used as the {@code [0] EXPLICIT hashAlgo} in {@link PrincipalUid} and as
 * {@code signatureAlgorithm} in {@link DelegationAuthorization}. {@code params}
 * holds the raw DER bytes of the optional parameters element (or {@code null}
 * when absent), matching Go's {@code asn1.RawValue} handling.
 */
public final class AlgorithmIdentifier {
    public final ASN1ObjectIdentifier oid;
    public final byte[] parameters;

    public AlgorithmIdentifier(ASN1ObjectIdentifier oid, byte[] parameters) {
        this.oid = Objects.requireNonNull(oid, "oid");
        this.parameters = parameters == null ? null : parameters.clone();
    }

    public AlgorithmIdentifier(ASN1ObjectIdentifier oid) {
        this(oid, null);
    }

    public boolean hasParameters() {
        return parameters != null;
    }

    public byte[] encode() {
        ASN1Encodable[] elems = parameters == null
                ? new ASN1Encodable[]{oid}
                : new ASN1Encodable[]{oid, fromParams(parameters)};
        return Der.der(new DERSequence(elems));
    }

    private static ASN1Encodable fromParams(byte[] raw) {
        try {
            return org.bouncycastle.asn1.ASN1Primitive.fromByteArray(raw);
        } catch (Exception ex) {
            throw new AicException("Invalid AlgorithmIdentifier parameters", ex);
        }
    }

    public static AlgorithmIdentifier decode(ASN1Encodable e) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(e);
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            byte[] params = null;
            if (seq.size() > 1) {
                params = seq.getObjectAt(1).toASN1Primitive().getEncoded();
            }
            return new AlgorithmIdentifier(oid, params);
        } catch (java.io.IOException ex) {
            throw new AicException("Bad AlgorithmIdentifier", ex);
        }
    }

    public static AlgorithmIdentifier parse(byte[] derBytes) {
        try {
            return decode(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(derBytes));
        } catch (Exception ex) {
            throw new AicException("Bad AlgorithmIdentifier DER", ex);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AlgorithmIdentifier)) {
            return false;
        }
        AlgorithmIdentifier that = (AlgorithmIdentifier) o;
        return this.oid.equals(that.oid) && Arrays.equals(this.parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oid) * 31 + Arrays.hashCode(parameters);
    }

    @Override
    public String toString() {
        return parameters == null ? oid.getId() : oid.getId() + " (params)";
    }
}