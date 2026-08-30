package com.varwof.aic.cert;

import com.varwof.aic.Aic;
import com.varwof.aic.Oids;
import com.varwof.aic.PrincipalAuthorization;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

/**
 * Convenience builders for the two certificate kinds in the AIC model:
 * principal certificates carrying a PrincipalAuthorization extension and agent
 * certificates carrying the (critical) AIC extension. Signer algorithm is
 * chosen from the issuer key type (ECDSA-with-SHA-256/384/512 for EC curves,
 * RSA-PSS SHA-256 for RSA, Ed25519 for Ed keys). All X.509 handling is Bouncy
 * Castle.
 */
public final class AicCertificateBuilder {
    private AicCertificateBuilder() {
    }

    /** BC content signer chosen from the key type. */
    public static ContentSigner contentSignerFor(PrivateKey key) {
        try {
            String alg;
            if (key instanceof java.security.interfaces.ECKey ec) {
                int bits = ec.getParams().getCurve().getField().getFieldSize();
                alg = bits >= 521 ? "SHA512withECDSA" : bits >= 384 ? "SHA384withECDSA" : "SHA256withECDSA";
            } else if (key instanceof java.security.interfaces.RSAKey) {
                alg = "SHA256withRSAandMGF1";
            } else if ("Ed25519".equals(key.getAlgorithm())) {
                alg = "Ed25519";
            } else {
                throw new com.varwof.aic.AicException("cert: unsupported signing key " + key.getAlgorithm());
            }
            return new JcaContentSignerBuilder(alg).setProvider("BC").build(key);
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: could not create content signer", ex);
        }
    }

    /** Build the raw X.509v3 Extension object for a {@link PrincipalAuthorization}. */
    public static Extension principalAuthorizationExtension(PrincipalAuthorization pa, boolean critical) {
        return new Extension(Oids.PRINCIPAL_AUTHORIZATION, critical, octets(pa.encode()));
    }

    public static Extension aicExtension(Aic aic, boolean critical) {
        return new Extension(Oids.AIC, critical, octets(aic.encode()));
    }

    private static ASN1OctetString octets(byte[] der) {
        return new DEROctetString(der);
    }

    /**
     * Self-signed principal certificate exposing the given
     * PrincipalAuthorization extension under the principal's own key.
     */
    public static X509CertificateHolder buildPrincipalCert(
            KeyPair principalKeys, PrincipalAuthorization pa, X500Name subject,
            BigInteger serial, Instant notBefore, Instant notAfter) {
        X500Name effectiveSubject = subject != null ? subject : new X500Name("CN=" + principalKeys.getPublic().hashCode());
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                effectiveSubject, serial, Date.from(notBefore), Date.from(notAfter),
                effectiveSubject, publicKeyInfo(principalKeys.getPublic()));
        try {
            b.addExtension(principalAuthorizationExtension(pa, false));
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        } catch (org.bouncycastle.cert.CertIOException ex) {
            throw new com.varwof.aic.AicException("cert: principal extension attach failed", ex);
        }
        try {
            return b.build(contentSignerFor(principalKeys.getPrivate()));
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: principal cert build failed", ex);
        }
    }

    /**
     * Issue an agent certificate from {@code issuerKeys} for {@code agentKeys}
     * carrying the (critical) AIC extension and an optional SPIFFE SAN.
     */
    public static X509CertificateHolder buildAgentCert(
            KeyPair issuerKeys, X500Name issuer, KeyPair agentKeys, Aic aic,
            X500Name subject, BigInteger serial, Instant notBefore, Instant notAfter,
            String spiffeSan) {
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                issuer != null ? issuer : new X500Name("CN=varwof-ca"),
                serial, Date.from(notBefore), Date.from(notAfter),
                subject != null ? subject : new X500Name("CN=" + aic.agentId()),
                publicKeyInfo(agentKeys.getPublic()));
        try {
            b.addExtension(aicExtension(aic, true));
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            if (spiffeSan != null && !spiffeSan.isEmpty()) {
                b.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, spiffeSan)));
            }
        } catch (org.bouncycastle.cert.CertIOException ex) {
            throw new com.varwof.aic.AicException("cert: agent extension attach failed", ex);
        }
        try {
            return b.build(contentSignerFor(issuerKeys.getPrivate()));
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: agent cert build failed", ex);
        }
    }

    /** Convenience: convert a BC holder to a JCA {@link X509Certificate}. */
    public static X509Certificate toJca(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: holder conversion failed", ex);
        }
    }

    /** SubjectPublicKeyInfo (SPKI) for a JCA public key (as Go's PKIX marshal). */
    public static SubjectPublicKeyInfo publicKeyInfo(PublicKey key) {
        try {
            return SubjectPublicKeyInfo.getInstance(key.getEncoded());
        } catch (Exception ex) {
            throw new com.varwof.aic.AicException("cert: SPKI derivation failed", ex);
        }
    }
}