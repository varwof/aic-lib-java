package com.varwof.aic;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DelegationAuthorization signing/verification and cross-field checks.
 */
class DelegationAuthCryptoTest {

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256, new SecureRandom());
        return g.generateKeyPair();
    }

    private static DelegationAuthTbs tbs() {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", new byte[32], null);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return new DelegationAuthTbs(1, "agent-109", pu,
                new Reason("http", "Need to query users"),
                List.of(new Capability("http", "GET:/api/v1/users", new byte[]{0x01})),
                DelegationMode.AUTHORIZED, List.of(), 3600,
                Instant.parse("2026-08-18T00:00:00Z"), nonce);
    }

    private static DelegationAuthTbs tbsWithNonce(byte[] nonce) {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", new byte[32], null);
        return new DelegationAuthTbs(1, "agent-109", pu,
                new Reason("http", "Need to query users"),
                List.of(new Capability("http", "GET:/api/v1/users", new byte[]{0x01})),
                DelegationMode.AUTHORIZED, List.of(), 3600,
                Instant.parse("2026-08-18T00:00:00Z"), nonce);
    }

    @Test
    void signAndVerifyEcRoundTrip() throws Exception {
        KeyPair keys = ecKeyPair();
        DelegationAuthTbs tbs = tbs();
        DelegationAuthorization da = DelegationAuthCrypto.sign(tbs, keys.getPrivate());
        assertTrue(da.isPresent());
        assertTrue(SigAlgorithms.isSupported(da.signatureAlgorithm().oid));
        assertTrue(DelegationAuthCrypto.verify(tbs, da, keys.getPublic()),
                "fresh signature must verify");
    }

    @Test
    void verifyRejectsTamperedTbs() throws Exception {
        KeyPair keys = ecKeyPair();
        DelegationAuthTbs tbs = tbs();
        DelegationAuthorization da = DelegationAuthCrypto.sign(tbs, keys.getPrivate());

        DelegationAuthTbs tampered = tbsWithNonce(tbs.nonce); // same content; agentId differs? no -
        // force an actual change in agentId:
        DelegationAuthTbs changed = new DelegationAuthTbs(1, "agent-OTHER", tbs.principalUid,
                tbs.reason, tbs.capabilities, tbs.delegationMode, tbs.authorizationConstraints,
                tbs.requestedLifetime, tbs.timestamp, tbs.nonce);
        assertFalse(DelegationAuthCrypto.verify(changed, da, keys.getPublic()));
        assertFalse(DelegationAuthCrypto.verify(tbs, new DelegationAuthorization(
                da.reason(), da.requestedLifetime(), da.timestamp(), da.nonce(),
                da.signatureAlgorithm(), new byte[64]), keys.getPublic()));
    }

    @Test
    void signingRequiresNonce() throws Exception {
        DelegationAuthTbs noNonce = tbsWithNonce(null);
        assertThrows(AicException.class, () -> DelegationAuthCrypto.sign(noNonce, ecKeyPair().getPrivate()));
    }

    @Test
    void verifyAicPipeline() throws Exception {
        KeyPair keys = ecKeyPair();
        byte[] hash = HashAlgorithms.keyHashFromSpki(Oids.SHA256,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()).getEncoded());
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", hash, null);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        DelegationAuthTbs tbs = new DelegationAuthTbs(1, "agent-109", pu,
                new Reason("http", "Need to query users"),
                List.of(new Capability("http", "GET:/api/v1/users", new byte[]{0x01})),
                DelegationMode.AUTHORIZED, List.of(), 3600,
                Instant.parse("2026-08-18T00:00:00Z"), nonce);

        Aic aic = new Aic(1, "agent-109", pu, tbs.capabilities, DelegationMode.AUTHORIZED, List.of(),
                DelegationAuthCrypto.sign(tbs, keys.getPrivate()), List.of());
        assertTrue(DelegationAuthCrypto.verifyAic(aic, keys.getPublic()));

        Aic evil = new Aic(1, "agent-OTHER", aic.principalUid(), aic.capabilities(),
                aic.delegationMode(), aic.authorizationConstraints(), aic.delegationAuthorization(), aic.extensions());
        assertFalse(DelegationAuthCrypto.verifyAic(evil, keys.getPublic()));
    }

    @Test
    void ecdsaDerRsConversion() throws Exception {
        KeyPair keys = ecKeyPair();
        DelegationAuthTbs tbs = tbs();
        DelegationAuthorization da = DelegationAuthCrypto.sign(tbs, keys.getPrivate());

        int size = Ecdsa.coordBytes(256);
        byte[] rs = Ecdsa.derToRs(da.signatureValue(), 256);
        assertTrue(rs.length == size * 2);
        byte[] back = Ecdsa.rsToDer(rs, 256);
        assertArrayEquals(da.signatureValue(), back, "DER<->rs must round trip");
    }
}