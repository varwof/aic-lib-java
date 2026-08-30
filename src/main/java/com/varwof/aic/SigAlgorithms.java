package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Mapping between X.509 signature AlgorithmIdentifiers and JCA signer/verifier
 * primitives, plus defaults chosen per key type. RSA keys default to RSASSA-PSS
 * with SHA-256 (the draft's preference), matching the member implementations;
 * ECDSA keys pick the digest matching their curve.
 */
public final class SigAlgorithms {
    private SigAlgorithms() {
    }

    static {
        // ensure the BouncyCastle provider is registered before any use
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** JCA signature algorithm name for a signature OID; throws when unsupported. */
    public static String jcaName(ASN1ObjectIdentifier oid) {
        if (Oids.ECDSA_WITH_SHA256.equals(oid)) {
            return "SHA256withECDSA";
        }
        if (Oids.ECDSA_WITH_SHA384.equals(oid)) {
            return "SHA384withECDSA";
        }
        if (Oids.ECDSA_WITH_SHA512.equals(oid)) {
            return "SHA512withECDSA";
        }
        if (Oids.RSA_WITH_SHA256.equals(oid)) {
            return "SHA256withRSA";
        }
        if (Oids.RSA_WITH_SHA384.equals(oid)) {
            return "SHA384withRSA";
        }
        if (Oids.RSA_WITH_SHA512.equals(oid)) {
            return "SHA512withRSA";
        }
        if (Oids.RSA_PSS.equals(oid)) {
            return "SHA256withRSAandMGF1"; // salt/hash configured explicitly by caller
        }
        if (Oids.ED25519.equals(oid)) {
            return "Ed25519";
        }
        throw new AicException("signature: unsupported algorithm OID " + oid);
    }

    /** Digest OID implied by a (non-PSS) signature OID, when applicable. */
    public static ASN1ObjectIdentifier digestOid(ASN1ObjectIdentifier sigOid) {
        if (Oids.ECDSA_WITH_SHA256.equals(sigOid) || Oids.RSA_WITH_SHA256.equals(sigOid)) {
            return Oids.SHA256;
        }
        if (Oids.ECDSA_WITH_SHA384.equals(sigOid) || Oids.RSA_WITH_SHA384.equals(sigOid)) {
            return Oids.SHA384;
        }
        if (Oids.ECDSA_WITH_SHA512.equals(sigOid) || Oids.RSA_WITH_SHA512.equals(sigOid)) {
            return Oids.SHA512;
        }
        return null; // PSS, Ed25519 -> none
    }

    public static boolean isSupported(ASN1ObjectIdentifier oid) {
        try {
            jcaName(oid);
            return true;
        } catch (AicException ex) {
            return false;
        }
    }

    /** Recommended signature OID for the given private key. */
    public static ASN1ObjectIdentifier forKey(PrivateKey key) {
        if (key instanceof ECKey) {
            int bits = curveBits((ECKey) key);
            if (bits >= 521) {
                return Oids.ECDSA_WITH_SHA512;
            }
            if (bits >= 384) {
                return Oids.ECDSA_WITH_SHA384;
            }
            return Oids.ECDSA_WITH_SHA256;
        }
        if (key instanceof RSAKey) {
            return Oids.RSA_PSS;
        }
        if ("Ed25519".equals(key.getAlgorithm())) {
            return Oids.ED25519;
        }
        throw new AicException("signature: unsupported key type " + key.getAlgorithm());
    }

    static int curveBits(ECKey key) {
        EllipticCurve curve = key.getParams().getCurve();
        return curve.getField().getFieldSize();
    }

    /** PSS parameters matching the digests used by the AIC family. */
    public static PSSParameterSpec pssParamSpec(ASN1ObjectIdentifier digestOid, String mdName) {
        int digestBits = HashAlgorithms.outputLength(digestOid) * 8;
        return new PSSParameterSpec(mdName, "MGF1", new MGF1ParameterSpec(mdName), digestBits / 8, 1);
    }

    static java.security.Signature signatureFor(ASN1ObjectIdentifier sigOid, String provider) throws NoSuchAlgorithmException {
        if (provider == null || provider.isEmpty()) {
            provider = null;
        }
        String name = jcaName(sigOid);
        try {
            return provider == null ? java.security.Signature.getInstance(name) : java.security.Signature.getInstance(name, provider);
        } catch (java.security.NoSuchProviderException ex) {
            throw new NoSuchAlgorithmException("provider " + provider + " missing: " + ex.getMessage());
        }
    }

    /** Verify a DER signature against a message, choosing JCA name + PSS param by OID. */
    public static boolean verify(ASN1ObjectIdentifier sigOid, PublicKey key, byte[] message, byte[] signature) {
        try {
            java.security.Signature sig = signatureFor(sigOid, "BC");
            if (Oids.RSA_PSS.equals(sigOid)) {
                sig.setParameter(pssParamSpec(Oids.SHA256, "SHA-256"));
            }
            if (Oids.ED25519.equals(sigOid) && signature.length != 64) {
                return false;
            }
            sig.initVerify(key);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception ex) {
            return false;
        }
    }
}