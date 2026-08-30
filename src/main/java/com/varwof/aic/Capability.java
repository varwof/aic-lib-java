package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Arrays;
import java.util.Objects;

/**
 * A protocolized capability container (draft §5.1 / Go {@code types.Capability}).
 *
 * <p>The full permission identifier is {@code schemeId + ":" + capabilityId}
 * ({@link #fullId()}) and all matching/authorization decisions MUST use it.
 * DER: {@code SEQUENCE { UTF8String schemeId, UTF8String capabilityId,
 * [0] EXPLICIT OCTET STRING OPTIONAL }}.
 */
public record Capability(String schemeId, String capabilityId, byte[] parameters) {

    public Capability {
        schemeId = Objects.requireNonNull(schemeId, "schemeId");
        capabilityId = Objects.requireNonNull(capabilityId, "capabilityId");
        parameters = parameters == null ? null : parameters.clone();
    }

    public Capability(String schemeId, String capabilityId) {
        this(schemeId, capabilityId, null);
    }

    /** Full permission identifier {@code scheme:capabilityId}. */
    public String fullId() {
        if (schemeId == null || schemeId.isEmpty()) {
            return capabilityId;
        }
        return schemeId + ":" + capabilityId;
    }

    public boolean hasParameters() {
        return parameters != null && parameters.length > 0;
    }

    public byte[] encode() {
        ASN1Encodable[] elems = hasParameters()
                ? new ASN1Encodable[]{
                Der.utf8(schemeId),
                Der.utf8(capabilityId),
                Der.explicit(0, new DEROctetString(parameters))}
                : new ASN1Encodable[]{Der.utf8(schemeId), Der.utf8(capabilityId)};
        return Der.der(Der.derSequence(elems));
    }

    public static Capability decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 2 || seq.size() > 3) {
            throw new AicException("Capability: expected 2-3 elements, got " + seq.size());
        }
        String scheme = Der.stringValue(seq.getObjectAt(0));
        String id = Der.stringValue(seq.getObjectAt(1));
        byte[] params = null;
        if (seq.size() == 3) {
            org.bouncycastle.asn1.ASN1Primitive inner = Der.optionalTagContent(seq.getObjectAt(2), 0);
            if (inner == null) {
                throw new AicException("Capability: third element must be [0] EXPLICIT OCTET STRING");
            }
            params = ASN1OctetString.getInstance(inner).getOctets();
        }
        return new Capability(scheme, id, params);
    }

    public static Capability parse(byte[] derBytes) {
        try {
            return decode(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("Capability: bad DER", ex);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Capability that)) {
            return false;
        }
        return schemeId.equals(that.schemeId)
                && capabilityId.equals(that.capabilityId)
                && Arrays.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        int result = schemeId.hashCode();
        result = 31 * result + capabilityId.hashCode();
        result = 31 * result + Arrays.hashCode(parameters);
        return result;
    }

    @Override
    public String toString() {
        return fullId();
    }
}