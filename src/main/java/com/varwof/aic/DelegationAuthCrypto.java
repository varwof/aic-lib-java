package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Signing and verification of the DelegationAuthorization TBS over a
 * principal/agent public key, per draft-wei-aic-identity-cert §3.
 *
 * <p>The signature input is the DER encoding of the {@link DelegationAuthTbs};
 * the signature AlgorithmIdentifier is recorded inside the DA so verification
 * is self-describing.
 */
public final class DelegationAuthCrypto {
    private DelegationAuthCrypto() {
    }

    /**
     * Sign the TBS with the principal's private key, producing a DA whose
     * reason/lifetime/timestamp/nonce mirror the TBS.
     */
    public static DelegationAuthorization sign(DelegationAuthTbs tbs, PrivateKey key,
                                               ASN1ObjectIdentifier sigOid) {
        if (tbs.nonce == null) {
            throw new AicException("DelegationAuthCrypto: TBS nonce is required");
        }
        byte[] input = tbs.encode();
        byte[] sig = computeSignature(sigOid, key, input);
        return new DelegationAuthorization(
                tbs.reason,
                tbs.requestedLifetime,
                tbs.timestamp,
                tbs.nonce,
                new AlgorithmIdentifier(sigOid),
                sig);
    }

    /** Convenience overload: pick the recommended algorithm for the key. */
    public static DelegationAuthorization sign(DelegationAuthTbs tbs, PrivateKey key) {
        return sign(tbs, key, SigAlgorithms.forKey(key));
    }

    public static byte[] computeSignature(ASN1ObjectIdentifier sigOid, PrivateKey key, byte[] input) {
        try {
            Signature sig = SigAlgorithms.signatureFor(sigOid, "BC");
            if (Oids.RSA_PSS.equals(sigOid)) {
                sig.setParameter(SigAlgorithms.pssParamSpec(Oids.SHA256, "SHA-256"));
            }
            sig.initSign(key);
            sig.update(input);
            return sig.sign();
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new AicException("signature: algorithm not available for " + sigOid, ex);
        } catch (java.security.InvalidKeyException | java.security.SignatureException | java.security.InvalidAlgorithmParameterException ex) {
            throw new AicException("signature: signing failed for " + sigOid + ": " + ex.getMessage(), ex);
        }
    }

    /**
     * Verify a DA against the TBS it claims to authorize: the TBS is re-encoded
     * exactly (byte-identical DER) and checked against the recorded signature.
     */
    public static boolean verify(DelegationAuthTbs tbs, DelegationAuthorization da, PublicKey principalKey) {
        if (da == null || da.signatureValue() == null || da.signatureAlgorithm() == null || principalKey == null) {
            return false;
        }
        ASN1ObjectIdentifier oid = da.signatureAlgorithm().oid;
        if (!SigAlgorithms.isSupported(oid)) {
            return false;
        }
        if (Oids.ED25519.equals(oid) && (da.signatureValue().length != 64)) {
            return false;
        }
        byte[] input = tbs.encode();
        return SigAlgorithms.verify(oid, principalKey, input, da.signatureValue());
    }

    /**
     * Verify the DA carried by an AIC, reconstructing the TBS from the AIC.
     * Returns false when the AIC has no present DA or the signature does not
     * verify.
     */
    public static boolean verifyAic(Aic aic, PublicKey principalKey) {
        DelegationAuthorization da = aic.delegationAuthorization();
        if (da == null || !da.isPresent() || principalKey == null) {
            return false;
        }
        DelegationAuthTbs tbs = DelegationAuthTbs.fromAic(aic);
        return verify(tbs, da, principalKey);
    }
}