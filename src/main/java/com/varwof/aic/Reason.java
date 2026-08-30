package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;

import java.util.Objects;

/**
 * Delegation authorization reason (audit/display only, not part of permission
 * decisions). Both fields are REQUIRED non-empty. DER:
 * {@code SEQUENCE { UTF8String reasonCode, UTF8String description }}.
 */
public record Reason(String reasonCode, String description) {

    public Reason {
        reasonCode = Objects.requireNonNull(reasonCode, "reasonCode");
        description = Objects.requireNonNull(description, "description");
    }

    public static final Reason EMPTY = new Reason("", "");

    public boolean isEmpty() {
        return reasonCode.isEmpty() && description.isEmpty();
    }

    public byte[] encode() {
        return Der.der(Der.derSequence(Der.utf8(reasonCode), Der.utf8(description)));
    }

    public static Reason decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() != 2) {
            throw new AicException("Reason: expected 2 elements, got " + seq.size());
        }
        return new Reason(Der.stringValue(seq.getObjectAt(0)), Der.stringValue(seq.getObjectAt(1)));
    }
}