package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.cert.X509Certificate;

/**
 * keyHash computation from SPKI DER bytes and certificates.
 * Mirrors Go {@code KeyHashFromCertSPKI} / {@code KeyHashFromSPKI}.
 */
public final class KeyHashUtil {
    private KeyHashUtil() {
    }

    /** SPKI SubjectPublicKeyInfo DER for a JCA certificate. */
    public static byte[] spkiDer(X509Certificate cert) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            return holder.getSubjectPublicKeyInfo().getEncoded();
        } catch (Exception ex) {
            throw new AicException("keyhash: could not extract SPKI from certificate", ex);
        }
    }

    /** SPKI SubjectPublicKeyInfo DER for a BC certificate holder. */
    public static byte[] spkiDer(X509CertificateHolder holder) {
        try {
            return holder.getSubjectPublicKeyInfo().getEncoded();
        } catch (Exception ex) {
            throw new AicException("keyhash: could not extract SPKI from certificate", ex);
        }
    }

    public static byte[] keyHashFromCert(ASN1ObjectIdentifier algo, X509Certificate cert) {
        return HashAlgorithms.keyHashFromSpki(algo, spkiDer(cert));
    }

    public static byte[] keyHashFromCert(ASN1ObjectIdentifier algo, X509CertificateHolder holder) {
        return HashAlgorithms.keyHashFromSpki(algo, spkiDer(holder));
    }
}