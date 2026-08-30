package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Future delegation-depth control extension (OID .1.1.4, draft §3.7).
 * {@code SEQUENCE { INTEGER chainDepth, INTEGER maxDepth }}. Currently an
 * advisory structure; enforcement is a future feature in both the Go and the
 * mobility SDKs.
 */
public record DelegationDepthControl(int chainDepth, int maxDepth) {

    public byte[] encode() {
        return Der.der(Der.derSequence(Der.integer(chainDepth), Der.integer(maxDepth)));
    }

    public static DelegationDepthControl decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() != 2) {
            throw new AicException("DelegationDepthControl: expected 2 elements, got " + seq.size());
        }
        return new DelegationDepthControl(
                Der.intValue(seq.getObjectAt(0)),
                Der.intValue(seq.getObjectAt(1)));
    }

    public static DelegationDepthControl parse(byte[] derBytes) {
        try {
            return decode(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("DelegationDepthControl: bad DER", ex);
        }
    }
}