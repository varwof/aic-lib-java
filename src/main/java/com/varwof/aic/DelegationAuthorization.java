package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Delegation authorization cryptographic evidence (draft §3 / Go
 * {@code types.DelegationAuthorization}).
 *
 * <p>Field order: reason, requestedLifetime, timestamp, nonce,
 * signatureAlgorithm, signatureValue. DER:
 * {@code SEQUENCE { Reason, INTEGER requestedLifetime (DEFAULT 0),
 * GeneralizedTime timestamp, OCTET STRING nonce,
 * AlgorithmIdentifier signatureAlgorithm, OCTET STRING signatureValue }}.
 */
public record DelegationAuthorization(
        Reason reason,
        int requestedLifetime,
        Instant timestamp,
        byte[] nonce,
        AlgorithmIdentifier signatureAlgorithm,
        byte[] signatureValue) {

    public DelegationAuthorization {
        reason = Objects.requireNonNull(reason, "reason");
        nonce = nonce == null ? null : nonce.clone();
        signatureAlgorithm = Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        signatureValue = signatureValue == null ? null : signatureValue.clone();
    }

    /** Mirrors Go {@code IsPresent()}. */
    public boolean isPresent() {
        return !reason.reasonCode().isEmpty()
                || !reason.description().isEmpty()
                || (signatureValue != null && signatureValue.length > 0)
                || (nonce != null && nonce.length > 0)
                || requestedLifetime > 0
                || timestamp != null;
    }

    public byte[] encode() {
        return Der.der(Der.derSequence(
                asn1OfReason(),
                Der.integer(requestedLifetime),
                Der.generalized(timestamp),
                new DEROctetString(nonce == null ? new byte[0] : nonce),
                asn1Of(signatureAlgorithm.encode()),
                new DEROctetString(signatureValue == null ? new byte[0] : signatureValue)));
    }

    private static org.bouncycastle.asn1.ASN1Primitive asn1Of(byte[] der) {
        try {
            return org.bouncycastle.asn1.ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("DelegationAuthorization: bad nested DER", ex);
        }
    }

    private org.bouncycastle.asn1.ASN1Primitive asn1OfReason() {
        return asn1Of(reason.encode());
    }

    public static DelegationAuthorization decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() != 6) {
            throw new AicException("DelegationAuthorization: expected 6 elements, got " + seq.size());
        }
        Reason reason = Reason.decode(seq.getObjectAt(0));
        int lifetime = Der.intValue(seq.getObjectAt(1));
        Instant ts = Der.toInstant(org.bouncycastle.asn1.ASN1GeneralizedTime.getInstance(seq.getObjectAt(2)));
        byte[] nonce = Der.octetValue(seq.getObjectAt(3));
        AlgorithmIdentifier sigAlgo = AlgorithmIdentifier.decode(seq.getObjectAt(4));
        byte[] sigValue = Der.octetValue(seq.getObjectAt(5));
        return new DelegationAuthorization(reason, lifetime, ts, nonce, sigAlgo, sigValue);
    }

    public static DelegationAuthorization parse(byte[] derBytes) {
        try {
            return decode(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("DelegationAuthorization: bad DER", ex);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DelegationAuthorization that)) {
            return false;
        }
        return requestedLifetime == that.requestedLifetime
                && reason.equals(that.reason)
                && Objects.equals(timestamp, that.timestamp)
                && Arrays.equals(nonce, that.nonce)
                && signatureAlgorithm.equals(that.signatureAlgorithm)
                && Arrays.equals(signatureValue, that.signatureValue);
    }

    @Override
    public int hashCode() {
        int result = reason.hashCode();
        result = 31 * result + requestedLifetime;
        result = 31 * result + Objects.hashCode(timestamp);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + signatureAlgorithm.hashCode();
        result = 31 * result + Arrays.hashCode(signatureValue);
        return result;
    }
}