package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Low-level ASN.1/DER helpers shared by the AIC model classes.
 *
 * <p>The encoding is byte-compatible with the Go reference implementation
 * (which always emits default fields, uses GeneralizedTime as
 * {@code YYYYMMDDHHMMSSZ} UTC and uses {@code [0] EXPLICIT} only where the
 * draft requires it). Use {@link #encodeCursor(Object)}/concrete decode
 * methods on the model classes, not raw BC calls, to stay interoperable.
 */
public final class Der {
    private Der() {
    }

    /** DER encoding of an INTEGER, as Go emits it (minimal encoding). */
    public static ASN1Integer integer(long v) {
        return new ASN1Integer(BigInteger.valueOf(v));
    }

    /** DER encoding of a UTF8String (Go uses UTF8String tag 12 for text). */
    public static DERUTF8String utf8(String s) {
        return new DERUTF8String(s);
    }

    /**
     * GeneralizedTime in the canonical {@code YYYYMMDDHHMMSSZ} UTC form that the
     * Go implementation emits (sub-second precision is dropped).
     */
    public static ASN1GeneralizedTime generalized(Instant t) {
        Instant truncated = t.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        String s = DateTimeFormatter.ofPattern("uuuuMMddHHmmss")
                .withZone(ZoneOffset.UTC)
                .format(truncated) + "Z";
        return new ASN1GeneralizedTime(s);
    }

    /** Empty optional {@code [tag EXPLICIT]} markers are omitted by the Go encoder. */
    public static ASN1TaggedObject explicit(int tag, ASN1Encodable value) {
        return new DERTaggedObject(true, tag, value);
    }

    /** Parse a timestamp encoded as GeneralizedTime back to an {@link Instant}. */
    public static Instant toInstant(ASN1GeneralizedTime gt) {
        try {
            return gt.getDate().toInstant();
        } catch (java.text.ParseException ex) {
            throw new AicException("GeneralizedTime: unparsable timestamp", ex);
        }
    }

    /** Safely read an optional [[[tag]]] EXPLICIT wrapper from a sequence element. */
    public static ASN1Encodable getExplicit(ASN1Sequence seq, int index) {
        ASN1TaggedObject t = ASN1TaggedObject.getInstance(seq.getObjectAt(index));
        if (!t.isExplicit() && t.getTagNo() != 0) {
            // older BC may wrap; fall back to explicit interpretation
        }
        ASN1Encodable inner = t.getExplicitBaseObject();
        if (inner == null) {
            inner = t.getBaseObject();
        }
        return inner;
    }

    /** Read an optional [tagno EXPLICIT] element, returning null when tag no match. */
    public static ASN1Primitive optionalTagContent(ASN1Encodable elem, int tagNo) {
        if (elem instanceof ASN1TaggedObject) {
            ASN1TaggedObject t = (ASN1TaggedObject) elem;
            if (t.getTagNo() == tagNo) {
                ASN1Encodable inner = t.getExplicitBaseObject();
                if (inner == null) {
                    inner = t.getBaseObject();
                }
                if (inner instanceof ASN1Primitive) {
                    return (ASN1Primitive) inner;
                }
                return inner.toASN1Primitive();
            }
        }
        return null;
    }

    public static int intValue(ASN1Encodable e) {
        return ASN1Integer.getInstance(e).intValueExact();
    }

    public static String stringValue(ASN1Encodable e) {
        ASN1UTF8String s = ASN1UTF8String.getInstance(e);
        return s.getString();
    }

    public static byte[] octetValue(ASN1Encodable e) {
        return ASN1OctetString.getInstance(e).getOctets();
    }

    public static ASN1ObjectIdentifier oidValue(ASN1Encodable e) {
        return ASN1ObjectIdentifier.getInstance(e);
    }

    /** Best-effort string for a raw UTF8String that may be absent. */
    public static String maybeString(ASN1Encodable nullable) {
        if (nullable == null) {
            return "";
        }
        return ASN1UTF8String.getInstance(nullable).getString();
    }

    public static ASN1Sequence seq(ASN1Encodable e) {
        return ASN1Sequence.getInstance(e);
    }

    /** Convenience: build a SEQUENCE from encodables. */
    public static DERSequence derSequence(ASN1Encodable... elems) {
        return new DERSequence(elems);
    }

    /** Convenience: encode an ASN1 object to its DER bytes. */
    public static byte[] der(ASN1Encodable e) {
        try {
            return e.toASN1Primitive().getEncoded();
        } catch (java.io.IOException ex) {
            throw new AicException("DER encoding failed", ex);
        }
    }
}