package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Signing and verification of the DelegationAuthorization TBS over a
 * principal/agent public key, per draft-wei-aic-identity-cert §3.
 *
 * <p>The signature input is the DER encoding of the {@link DelegationAuthTBS};
 * the signature AlgorithmIdentifier is recorded inside the DA so verification
 * is self-describing.
 */
public final class DelegationAuthCrypto {
    public static final int DA_VERSION1 = 1;
    public static final int DA_VERSION2 = 2;

    private DelegationAuthCrypto() {
    }

    /**
     * Build an {@link AgentKeyBinding} from an agent SPKI DER digest.
     * When {@code oid} is null/empty, SHA-256 is used as default.
     *
     * @throws AicException on empty spkiDer or unsupported algorithm
     */
    public static AgentKeyBinding makeAgentKeyBinding(ASN1ObjectIdentifier oid, byte[] spkiDer) {
        if (spkiDer == null || spkiDer.length == 0) {
            throw new AicException("agent_key_binding: empty agent SPKI DER");
        }
        ASN1ObjectIdentifier algo = (oid == null || oid.equals(new ASN1ObjectIdentifier("0.0.0.0.0"))) ? null : oid;
        if (algo == null || algo.toString().isEmpty()) {
            algo = Oids.SHA256;
        }
        if (HashAlgorithms.nameForOid(algo).isEmpty()) {
            throw new AicException("agent_key_binding: unsupported hashAlgo " + algo);
        }
        byte[] keyHash = HashAlgorithms.keyHashFromSpki(algo, spkiDer);
        return new AgentKeyBinding(keyHash, new AlgorithmIdentifier(algo));
    }

    /** Convenience overload: default SHA-256. */
    public static AgentKeyBinding makeAgentKeyBinding(byte[] spkiDer) {
        return makeAgentKeyBinding(null, spkiDer);
    }

    /**
     * Validate an agent key binding: keyHash length 1..64, matching the
     * declared hashAlgo output length.
     */
    public static void validateAgentKeyBinding(AgentKeyBinding b) {
        if (b == null || b.isZero()) {
            throw new AicException("agent_key_binding: keyHash required for DA version 2");
        }
        ASN1ObjectIdentifier algo = b.hashAlgoOid();
        String name = HashAlgorithms.nameForOid(algo);
        if (name.isEmpty()) {
            throw new AicException("agent_key_binding: hashAlgo " + algo.getId() + ": unsupported keyHash algorithm");
        }
        Integer want = HashAlgorithms.outputLength(algo);
        if (want == null) {
            throw new AicException("agent_key_binding: hashAlgo " + algo.getId() + ": no output length mapping");
        }
        if (b.keyHash.length < 1 || b.keyHash.length > 64) {
            throw new AicException("agent_key_binding: keyHash length " + b.keyHash.length + ": must be 1-64");
        }
        if (b.keyHash.length != want) {
            throw new AicException("agent_key_binding: keyHash length " + b.keyHash.length
                    + ": must be " + want + " (" + name + ")");
        }
    }

    /**
     * Validate the DA version matrix:
     * version 1 (or 0) → agentKeyBinding MUST be absent;
     * version 2 → agentKeyBinding MUST be present and valid;
     * any other version → rejected.
     */
    public static void validateDelegationAuthTbsVersion(DelegationAuthTbs tbs) {
        if (tbs == null) {
            throw new AicException("delegation_auth_tbs: nil");
        }
        int version = tbs.version;
        if (version == 0) {
            version = DA_VERSION1;
        }
        switch (version) {
            case DA_VERSION1 -> {
                if (tbs.agentKeyBinding != null && !tbs.agentKeyBinding.isZero()) {
                    throw new AicException("delegation_auth_tbs: version 1: agentKeyBinding must be absent");
                }
            }
            case DA_VERSION2 -> {
                if (tbs.agentKeyBinding == null || tbs.agentKeyBinding.isZero()) {
                    throw new AicException("delegation_auth_tbs: version 2: agentKeyBinding is required");
                }
                validateAgentKeyBinding(tbs.agentKeyBinding);
            }
            default -> throw new AicException("delegation_auth_tbs: unsupported version " + tbs.version + ": must be 1 or 2");
        }
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
        validateDelegationAuthTbsVersion(tbs);
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
        validateDelegationAuthTbsVersion(tbs);
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
