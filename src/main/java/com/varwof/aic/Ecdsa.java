package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * ECDSA signature conversions between ASN.1 DER {@code SEQUENCE {r, s}} (X.509 /
 * DelegationAuthorization form) and the fixed-length {@code r||s} form used by
 * JOSE (ES256/384/512). Port of the conventions in Go's crypto/ecdsa usage.
 */
public final class Ecdsa {
    private Ecdsa() {
    }

    /** Convert a DER ECDSA signature to fixed-size {@code r||s}. */
    public static byte[] derToRs(byte[] der, int fieldSize) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(der));
            if (seq.size() != 2) {
                throw new AicException("ecdsa: DER signature must contain exactly 2 integers");
            }
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            int size = (fieldSize + 7) / 8;
            byte[] out = new byte[size * 2];
            byte[] rb = toFixed(r, size);
            byte[] sb = toFixed(s, size);
            System.arraycopy(rb, 0, out, 0, size);
            System.arraycopy(sb, 0, out, size, size);
            return out;
        } catch (AicException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AicException("ecdsa: invalid DER signature", ex);
        }
    }

    /** Convert a fixed-size {@code r||s} signature to DER. */
    public static byte[] rsToDer(byte[] rs, int fieldSize) {
        int size = (fieldSize + 7) / 8;
        if (rs == null || rs.length != size * 2) {
            throw new AicException("ecdsa: raw signature length " + (rs == null ? 0 : rs.length)
                    + " must be " + (size * 2));
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, size));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, size, size * 2));
        return Der.der(Der.derSequence(new ASN1Integer(r), new ASN1Integer(s)));
    }

    private static byte[] toFixed(BigInteger v, int size) {
        byte[] bare = v.toByteArray();
        byte[] out = new byte[size];
        if (bare.length == size) {
            System.arraycopy(bare, 0, out, 0, size);
        } else if (bare.length < size) {
            System.arraycopy(bare, 0, out, size - bare.length, bare.length);
        } else {
            // a leading zero sign byte may exceed size
            if (bare.length == size + 1 && bare[0] == 0) {
                System.arraycopy(bare, 1, out, 0, size);
            } else {
                throw new AicException("ecdsa: r/s value longer than field size");
            }
        }
        return out;
    }

    /** Fixed coord size (bytes) for a key whose field is {@code bits} wide. */
    public static int coordBytes(int fieldBits) {
        return (fieldBits + 7) / 8;
    }
}