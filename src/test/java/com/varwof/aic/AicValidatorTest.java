package com.varwof.aic;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port of Go {@code ValidateAIC} / {@code ValidatePrincipalAuthorization}
 * behaviour: accept the canonical AIC, reject each spec violation.
 */
class AicValidatorTest {

    private static byte[] keyHash() {
        byte[] k = new byte[32];
        for (int i = 0; i < k.length; i++) {
            k[i] = (byte) i;
        }
        return k;
    }

    private static byte[] nonce() {
        byte[] n = new byte[32];
        for (int i = 0; i < n.length; i++) {
            n[i] = (byte) i;
        }
        return n;
    }

    private static Aic validAic() {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(), null);
        DelegationAuthorization da = new DelegationAuthorization(
                new Reason("http", "Need to query users"), 3600,
                Instant.parse("2026-08-18T00:00:00Z"), nonce(),
                new AlgorithmIdentifier(Oids.ECDSA_WITH_SHA256), new byte[70]);
        return new Aic(1, "agent-109", pu,
                List.of(new Capability("http", "GET:/api/v1/users")),
                DelegationMode.AUTHORIZED, List.of(), da, List.of());
    }

    @Test
    void validAicPasses() {
        assertDoesNotThrow(() -> AicValidator.validate(validAic()));
    }

    @Test
    void agentIdEmptyRejected() {
        Aic a = validAic();
        Aic bad = new Aic(a.version(), "", a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), a.delegationAuthorization(), a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void missingDaRejected() {
        Aic a = validAic();
        Aic noDa = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), null, a.extensions());
        AicException ex = assertThrows(AicException.class, () -> AicValidator.validate(noDa));
        assertTrue(ex.getMessage().contains("delegationAuthorization is required"));
    }

    @Test
    void reasonMustBeNonEmpty() {
        Aic a = validAic();
        DelegationAuthorization da = a.delegationAuthorization();
        DelegationAuthorization badReason = new DelegationAuthorization(
                new Reason("", da.reason().description()), da.requestedLifetime(), da.timestamp(),
                da.nonce(), da.signatureAlgorithm(), da.signatureValue());
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), badReason, a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void nonceLengthMustBe32() {
        Aic a = validAic();
        DelegationAuthorization da = a.delegationAuthorization();
        DelegationAuthorization badNonce = new DelegationAuthorization(da.reason(), da.requestedLifetime(),
                da.timestamp(), new byte[16], da.signatureAlgorithm(), da.signatureValue());
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), badNonce, a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void requestedLifetimeBounds() {
        Aic a = validAic();
        DelegationAuthorization da = a.delegationAuthorization();
        // 86401 > max 86400 -> rejected
        DelegationAuthorization tooLong = new DelegationAuthorization(da.reason(), 86401, da.timestamp(),
                da.nonce(), da.signatureAlgorithm(), da.signatureValue());
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), tooLong, a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
        // 0 is upgraded to 3600 and accepted (matches Go: lifetime < 1 fails, 0 handled specially)
        DelegationAuthorization zero = new DelegationAuthorization(da.reason(), 0, da.timestamp(),
                da.nonce(), da.signatureAlgorithm(), da.signatureValue());
        Aic ok = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), zero, a.extensions());
        assertDoesNotThrow(() -> AicValidator.validate(ok));
        // negative -> rejected
        DelegationAuthorization negative = new DelegationAuthorization(da.reason(), -1, da.timestamp(),
                da.nonce(), da.signatureAlgorithm(), da.signatureValue());
        Aic neg = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), negative, a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(neg));
    }

    @Test
    void constraintSchemeWhitelist() {
        Aic a = validAic();
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                List.of(new Capability("evil-scheme", "x", new byte[]{0x01})),
                a.delegationAuthorization(), a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void constraintParamsMustBeValidJson() {
        Aic a = validAic();
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                List.of(new Capability("varwof/constraint-v1", "x", new byte[]{0x01, (byte) 0xc3})),
                a.delegationAuthorization(), a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void capabilitiesMustNotUseConstraintScheme() {
        Aic a = validAic();
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(),
                List.of(new Capability("varwof/constraint-v1", "allowed-cidr", "[]".getBytes())),
                a.delegationMode(), a.authorizationConstraints(), a.delegationAuthorization(), a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void keyHashMustMatchHashAlgoLength() {
        Aic a = validAic();
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", new byte[16], null);
        Aic bad = new Aic(a.version(), a.agentId(), pu, a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), a.delegationAuthorization(), a.extensions());
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void unknownCriticalExtensionRejected() {
        Aic a = validAic();
        ExtField unknown = new ExtField(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5"),
                true, new byte[]{0x01});
        Aic bad = new Aic(a.version(), a.agentId(), a.principalUid(), a.capabilities(), a.delegationMode(),
                a.authorizationConstraints(), a.delegationAuthorization(), List.of(unknown));
        assertThrows(AicException.class, () -> AicValidator.validate(bad));
    }

    @Test
    void maxConcurrentValidation() {
        assertDoesNotThrow(() -> AicValidator.validateMaxConcurrentParam("{\"max\": 16}".getBytes()));
        assertThrows(AicException.class,
                () -> AicValidator.validateMaxConcurrentParam("{\"max\": 0}".getBytes()));
        assertThrows(AicException.class,
                () -> AicValidator.validateMaxConcurrentParam("{\"max\": 1025}".getBytes()));
        assertThrows(AicException.class,
                () -> AicValidator.validateMaxConcurrentParam("not-json".getBytes()));
        // empty = not configured
        assertDoesNotThrow(() -> AicValidator.validateMaxConcurrentParam(new byte[0]));
    }

    @Test
    void principalAuthorizationValidation() {
        assertDoesNotThrow(() -> PrincipalAuthorizationValidator.validate(
                new PrincipalAuthorization(1,
                        List.of(new Capability("database", "query:SELECT")),
                        List.of(new Capability("varwof/constraint-v1", "allowed-cidr", "[]".getBytes())),
                        new DelegationPolicy(1, 8, 1, null), List.of())));
        assertThrows(AicException.class, () -> PrincipalAuthorizationValidator.validate(
                new PrincipalAuthorization(1,
                        List.of(new Capability("bad", "grant")),
                        List.of(new Capability("not-constraint", "x")), null, List.of())));
        assertThrows(AicException.class, () -> PrincipalAuthorizationValidator.validate(
                new PrincipalAuthorization(1, List.of(), List.of(),
                        new DelegationPolicy(1, 8, 2, null), List.of())));
    }

    @Test
    void principalUidDisplayFormat() {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(), null);
        String s = pu.displayString();
        // parseDisplayString assigns the explicit SHA-256 hashAlgo (as Go does)
        assertEquals(new PrincipalUid(1, "corp.com", "zhangsan", keyHash(), new AlgorithmIdentifier(Oids.SHA256)),
                PrincipalUid.parseDisplayString(s));
        assertThrows(AicException.class, () -> PrincipalUid.parseDisplayString("corp.com:zhangsan"));
        assertThrows(AicException.class, () -> PrincipalUid.parseDisplayString("a:b:c:d"));
    }
}