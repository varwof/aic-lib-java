package com.varwof.aic.cert;

import com.varwof.aic.Aic;
import com.varwof.aic.Oids;
import com.varwof.aic.PrincipalAuthorization;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;

/**
 * Extraction of the AIC and PrincipalAuthorization extensions from X.509
 * certificates. Port of Go {@code ParseAIC} / {@code ParseUserPermissionExtension}.
 */
public final class AicCertificates {
    private AicCertificates() {
    }

    public static boolean hasAicExtension(org.bouncycastle.asn1.x509.Extensions exts) {
        return exts != null && exts.getExtension(Oids.AIC) != null;
    }

    public static boolean hasAicExtension(X509CertificateHolder holder) {
        return holder != null && holder.getExtension(Oids.AIC) != null;
    }

    /** Parse the AIC extension and validate its content (combines parseAic + AicValidator.validate). */
    public static Aic parseAndValidateAic(X509CertificateHolder holder) {
        Aic aic = parseAic(holder);
        com.varwof.aic.AicValidator.validate(aic);
        return aic;
    }

    public static Aic parseAndValidateAic(java.security.cert.X509Certificate cert) {
        Aic aic = parseAic(cert);
        com.varwof.aic.AicValidator.validate(aic);
        return aic;
    }

    /** Parse and validate the PrincipalAuthorization extension; returns null when absent. */
    public static PrincipalAuthorization parseAndValidatePrincipalAuthorization(X509CertificateHolder holder) {
        PrincipalAuthorization pa = parsePrincipalAuthorization(holder);
        if (pa != null) {
            com.varwof.aic.PrincipalAuthorizationValidator.validate(pa);
        }
        return pa;
    }

    public static PrincipalAuthorization parseAndValidatePrincipalAuthorization(java.security.cert.X509Certificate cert)
            throws IOException {
        PrincipalAuthorization pa = parsePrincipalAuthorization(cert);
        if (pa != null) {
            com.varwof.aic.PrincipalAuthorizationValidator.validate(pa);
        }
        return pa;
    }

    /** Parse the AIC extension value; throws when absent or malformed. */
    public static Aic parseAic(X509CertificateHolder holder) {
        if (holder == null) {
            throw new com.varwof.aic.AicException("aic: nil certificate");
        }
        org.bouncycastle.asn1.x509.Extension ext = holder.getExtension(Oids.AIC);
        if (ext == null) {
            throw new com.varwof.aic.AicException("aic: AIC extension not present");
        }
        return Aic.parse(ext.getExtnValue().getOctets());
    }

    public static Aic parseAic(java.security.cert.X509Certificate cert) {
        byte[] value = extensionValue(cert, Oids.AIC);
        if (value == null) {
            throw new com.varwof.aic.AicException("aic: AIC extension not present");
        }
        return Aic.parse(value);
    }

    /** Parse the PrincipalAuthorization extension; returns null when absent. */
    public static PrincipalAuthorization parsePrincipalAuthorization(X509CertificateHolder holder) {
        if (holder == null) {
            return null;
        }
        org.bouncycastle.asn1.x509.Extension ext = holder.getExtension(Oids.PRINCIPAL_AUTHORIZATION);
        if (ext == null) {
            return null;
        }
        return PrincipalAuthorization.parse(ext.getExtnValue().getOctets());
    }

    public static PrincipalAuthorization parsePrincipalAuthorization(java.security.cert.X509Certificate cert)
            throws IOException {
        byte[] value = extensionValue(cert, Oids.PRINCIPAL_AUTHORIZATION);
        if (value == null) {
            return null;
        }
        return PrincipalAuthorization.parse(value);
    }

    private static byte[] extensionValue(java.security.cert.X509Certificate cert, org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
        if (cert == null) {
            return null;
        }
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            org.bouncycastle.asn1.x509.Extension ext = holder.getExtension(oid);
            return ext == null ? null : ext.getExtnValue().getOctets();
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: could not read extension " + oid, ex);
        }
    }
}