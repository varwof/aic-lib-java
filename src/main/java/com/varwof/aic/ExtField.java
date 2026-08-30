package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Arrays;
import java.util.Objects;

/**
 * A single extension slot inside {@code AIC.extensions}.
 * DER: {@code SEQUENCE { OID extnId, BOOLEAN critical (default FALSE),
 * OCTET STRING extnValue }}. Like the Go reference (no {@code omitempty} on the
 * BOOLEAN), critical is always emitted.
 */
public record ExtField(ASN1ObjectIdentifier extnId, boolean critical, byte[] extnValue) {

    public ExtField {
        extnId = Objects.requireNonNull(extnId, "extnId");
        extnValue = Objects.requireNonNull(extnValue, "extnValue");
    }

    public byte[] encode() {
        return Der.der(Der.derSequence(
                extnId,
                ASN1Boolean.getInstance(critical),
                new DEROctetString(extnValue)));
    }

    public static ExtField decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() != 3) {
            throw new AicException("ExtField: expected 3 elements, got " + seq.size());
        }
        ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        boolean crit = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue();
        byte[] value = Der.octetValue(seq.getObjectAt(2));
        return new ExtField(id, crit, value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ExtField that)) {
            return false;
        }
        return critical == that.critical
                && extnId.equals(that.extnId)
                && Arrays.equals(extnValue, that.extnValue);
    }

    @Override
    public int hashCode() {
        int result = extnId.hashCode();
        result = 31 * result + (critical ? 1 : 0);
        result = 31 * result + Arrays.hashCode(extnValue);
        return result;
    }
}