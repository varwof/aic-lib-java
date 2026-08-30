package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

import java.util.ArrayList;
import java.util.List;

/**
 * Delegation policy inside PrincipalAuthorization (Go {@code types.DelegationPolicy}).
 * DER: {@code SEQUENCE { INTEGER version (DEFAULT 1), INTEGER maxAgents (DEFAULT 1),
 * INTEGER allowedMode (DEFAULT 0), [0] EXPLICIT INTEGER maxSessionHours OPTIONAL }}.
 */
public record DelegationPolicy(int version, int maxAgents, int allowedMode, Integer maxSessionHours) {

    public static final DelegationPolicy DEFAULT = new DelegationPolicy(1, 1, 0, null);

    public boolean allowsRepresentative() {
        return allowedMode == 1;
    }

    public byte[] encode() {
        List<ASN1Encodable> elems = new ArrayList<>();
        elems.add(Der.integer(version));
        elems.add(Der.integer(maxAgents));
        elems.add(Der.integer(allowedMode));
        if (maxSessionHours != null) {
            elems.add(Der.explicit(0, Der.integer(maxSessionHours)));
        }
        return Der.der(Der.derSequence(elems.toArray(new ASN1Encodable[0])));
    }

    public static DelegationPolicy decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 3 || seq.size() > 4) {
            throw new AicException("DelegationPolicy: expected 3-4 elements, got " + seq.size());
        }
        int version = Der.intValue(seq.getObjectAt(0));
        int maxAgents = Der.intValue(seq.getObjectAt(1));
        int allowedMode = Der.intValue(seq.getObjectAt(2));
        Integer maxSessionHours = null;
        if (seq.size() == 4) {
            ASN1Primitive inner = Der.optionalTagContent(seq.getObjectAt(3), 0);
            if (inner == null) {
                throw new AicException("DelegationPolicy: fourth element must be [0] EXPLICIT INTEGER");
            }
            maxSessionHours = Der.intValue(inner);
        }
        return new DelegationPolicy(version, maxAgents, allowedMode, maxSessionHours);
    }
}