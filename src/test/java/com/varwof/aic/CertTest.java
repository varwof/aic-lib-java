package com.varwof.aic;

import com.varwof.aic.cert.AicCertificateBuilder;
import com.varwof.aic.cert.AicCertificates;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Certificate construction and extension extraction round trips.
 */
class CertTest {

    private static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256, new java.security.SecureRandom());
        return g.generateKeyPair();
    }

    @Test
    void principalCertRoundTrip() throws Exception {
        KeyPair keys = ec();
        PrincipalAuthorization pa = new PrincipalAuthorization(1,
                List.of(new Capability("database", "query:SELECT")),
                List.of(), new DelegationPolicy(1, 8, 1, null), List.of());
        Instant now = Instant.parse("2026-08-18T00:00:00Z");
        X509CertificateHolder holder = AicCertificateBuilder.buildPrincipalCert(
                keys, pa, new org.bouncycastle.asn1.x500.X500Name("CN=principal-zhangsan"),
                BigInteger.ONE, now, now.plusSeconds(3600));
        PrincipalAuthorization parsed = AicCertificates.parsePrincipalAuthorization(holder);
        assertEquals(pa.grantIds(), parsed.grantIds());
        assertEquals(pa.delegationPolicy(), parsed.delegationPolicy());
    }

    @Test
    void agentCertRoundTrip() throws Exception {
        KeyPair ca = ec();
        KeyPair agent = ec();
        byte[] hash = HashAlgorithms.keyHashFromSpki(Oids.SHA256,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(ca.getPublic().getEncoded()).getEncoded());
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", hash, null);
        DelegationAuthTbs tbs = new DelegationAuthTbs(1, "agent-109", pu,
                new Reason("http", "Need to query users"),
                List.of(new Capability("http", "GET:/api/v1/users", new byte[]{0x01})),
                DelegationMode.AUTHORIZED, List.of(), 3600,
                Instant.parse("2026-08-18T00:00:00Z"), new byte[32]);
        Aic aic = new Aic(1, "agent-109", pu, tbs.capabilities, DelegationMode.AUTHORIZED, List.of(),
                DelegationAuthCrypto.sign(tbs, ca.getPrivate()), List.of());
        Instant now = Instant.parse("2026-08-18T00:00:00Z");
        X509CertificateHolder holder = AicCertificateBuilder.buildAgentCert(
                ca, new org.bouncycastle.asn1.x500.X500Name("CN=varwof-ca"), agent, aic,
                new org.bouncycastle.asn1.x500.X500Name("CN=agent-109"),
                BigInteger.valueOf(42), now, now.plusSeconds(3600),
                "spiffe://varwof.com/agent/agent-109");
        Aic parsed = AicCertificates.parseAic(holder);
        assertEquals(aic.agentId(), parsed.agentId());
        assertEquals(aic.principal(), parsed.principal());
        assertEquals(aic.capabilities(), parsed.capabilities());
        assertTrue(parsed.delegationAuthorization().isPresent());
        assertNull(AicCertificates.parsePrincipalAuthorization(holder));
    }
}