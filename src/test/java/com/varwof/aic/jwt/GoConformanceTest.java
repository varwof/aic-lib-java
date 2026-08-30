package com.varwof.aic.jwt;

import com.varwof.aic.AicException;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-language conformance: a token generated and signed by the Go
 * reference implementation must validate end-to-end in this Java port,
 * including key-binding (SPKI hash), JWK thumbprint and signature checks.
 */
class GoConformanceTest {

    private static final long IAT = 1755500000L;

    private static final String OUTER_TOKEN = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImFpYytqd3QiLCJraWQiOiJjYS0yMDI2LTAxIn0.eyJpc3MiOiJodHRwczovL2NhLmV4YW1wbGUuY29tL2FpYyIsInN1YiI6ImFnZW50OmRiLWFuYWx5c3QtMDEiLCJhdWQiOlsiaHR0cHM6Ly9ndy5leGFtcGxlLmNvbSJdLCJpYXQiOjE3NTU1MDAwMDAsImV4cCI6MTc1NTUwMzYwMCwianRpIjoiXy0temQzM0YtSzBvUVFISVo3T0drRS1hZlRDNFBveXRhbXJMWlo4M0dTWSIsImNuZiI6eyJqa3QiOiJac0ltcXhzNGo4THFHeUFLTTE0cnlGbWJBdFM0Vk1aT0RXLWVnQ2VJd3pvIn0sImFpYyI6eyJ2ZXIiOjEsInByaW5jaXBhbCI6eyJyZWFsbSI6ImNvcnAuY29tIiwiaWQiOiJ6aGFuZ3NhbiIsImtleV9oYXNoIjoiTUx5SWx1N1ZSY1h1OUk5SngxMWp6OS1TZVVTVFhJSzZtU0w4WGRsaDJUWSIsImhhc2hfYWxnIjoic2hhLTI1NiJ9LCJkZWxlZ2F0aW9uX21vZGUiOiJhdXRob3JpemVkIiwiY2FwYWJpbGl0aWVzIjpbeyJzY2hlbWUiOiJkYXRhYmFzZSIsImlkIjoicXVlcnk6U0VMRUNUIiwicGFyYW1zIjp7Im1heF9yb3dzIjoxMDB9fV0sImNvbnN0cmFpbnRzIjpbeyJzY2hlbWUiOiJ2YXJ3b2YvY29uc3RyYWludC12MSIsImlkIjoiYWxsb3dlZC1jaWRyIiwicGFyYW1zIjpbIjEwLjAuMC4wLzgiXX1dLCJjaGFpbl9kZXB0aCI6MCwibWF4X2RlcHRoIjoxfSwiZGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW1GcFl5dGtZU3RxZDNRaUxDSnJhV1FpT2lKd2NtbHVZMmx3WVd3dGVtaGhibWR6WVc0dE1qQXlOaUo5LmV5SjJaWElpT2pFc0ltRm5aVzUwWDJsa0lqb2lZV2RsYm5RNlpHSXRZVzVoYkhsemRDMHdNU0lzSW5CeWFXNWphWEJoYkNJNmV5SnlaV0ZzYlNJNkltTnZjbkF1WTI5dElpd2lhV1FpT2lKNmFHRnVaM05oYmlJc0ltdGxlVjlvWVhOb0lqb2lUVXg1U1d4MU4xWlNZMWgxT1VrNVNuZ3hNV3A2T1MxVFpWVlRWRmhKU3padFUwdzRXR1JzYURKVVdTSXNJbWhoYzJoZllXeG5Jam9pYzJoaExUSTFOaUo5TENKeVpXRnpiMjRpT25zaVkyOWtaU0k2SWtSQlZFRmZRVTVCVEZsVFNWTWlMQ0prWlhOaklqb2lVMk5vWldSMWJHVmtJSEJ5YjJSMVkzUnBiMjRnWkdGMFlTQmhibUZzZVhOcGN5QjNhVzVrYjNjaWZTd2lZMkZ3WVdKcGJHbDBhV1Z6SWpwYmV5SnpZMmhsYldVaU9pSmtZWFJoWW1GelpTSXNJbWxrSWpvaWNYVmxjbms2VTBWTVJVTlVJaXdpY0dGeVlXMXpJanA3SW0xaGVGOXliM2R6SWpveE1EQjlmVjBzSW1SbGJHVm5ZWFJwYjI1ZmJXOWtaU0k2SW1GMWRHaHZjbWw2WldRaUxDSmpiMjV6ZEhKaGFXNTBjeUk2VzNzaWMyTm9aVzFsSWpvaWRtRnlkMjltTDJOdmJuTjBjbUZwYm5RdGRqRWlMQ0pwWkNJNkltRnNiRzkzWldRdFkybGtjaUlzSW5CaGNtRnRjeUk2V3lJeE1DNHdMakF1TUM4NElsMTlYU3dpY21WeGRXVnpkR1ZrWDJ4cFptVjBhVzFsSWpvek5qQXdMQ0owY3lJNk1UYzFOVFE1T1Rrd01Dd2libTl1WTJVaU9pSmZMUzE2WkRNelJpMUxNRzlSVVVoSldqZFBSMnRGTFdGbVZFTTBVRzk1ZEdGdGNreGFXamd6UjFOWkluMC5yTEtiNDRxaEJScHhyVnlqWHpEbXdORGhxblpZT0tGU0tieEd4OXNfYUlfbGZpN2hUTTQ3ckZldF9JdWFROEJCbUE4ZTk3V1ZQZzJyazQyekpIOXhGZyJ9.Uy3xYrWfOvP3qI1yc8ZPQAwfgzfYTkVk-NIVY0xrM1ZJ-DqoPM2CSK1PKmLa1zxPJgydhBgNCX9bcoCLn09qUw";
    private static final String PRINCIPAL_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5S3vtaVPAo+7ivmxKJtyF9XMG+SMAifqLqAXkFxPyowdzP3trO399nvmAoCZD4oLQffTCMb+rPEMSQEYBi0pAg==";
    private static final String CA_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUV8M50RyNg+/0dDB3W4BxlCuujwGQoL3fXhfYPzAFYcF9Yq1q08uxt6RLlFPSWIcD/CL1MX4G1eP77SXgESzvA==";
    private static final String EXPECTED_KEY_HASH = "MLyIlu7VRcXu9I9Jx11jz9-SeUSTXIK6mSL8Xdlh2TY";
    private static final String EXPECTED_JKT = "ZsImqxs4j8LqGyAKM14ryFmbAtS4VMZODW-egCeIwzo";

    private static PublicKey pubKey(String spkiB64) throws Exception {
        byte[] der = Base64.getDecoder().decode(spkiB64);
        return KeyFactory.getInstance("X.509").generatePublic(new X509EncodedKeySpec(der));
    }

    @Test
    void goTokenValidatesEndToEnd() throws Exception {
        PublicKey principalPub = pubKey(PRINCIPAL_SPKI_B64);
        PublicKey caPub = pubKey(CA_SPKI_B64);

        // key binding primitives agree with the Go reference implementation
        assertEquals(EXPECTED_KEY_HASH, KeyHash.spkiHashPub(principalPub, "sha-256"));
        assertEquals(EXPECTED_JKT, KeyHash.keyHashOf(principalPub, "jkt"));
        // JWK round trip produces the same SPKI
        assertArrayEquals(principalPub.getEncoded(),
                KeyHash.jwkToPublic(KeyHash.publicKeyToJwk(principalPub)).getEncoded());

        Validator.VerifyOptions opts = new Validator.VerifyOptions();
        opts.now = Instant.ofEpochSecond(IAT + 60);
        opts.expectedIssuer = "https://ca.example.com/aic";
        opts.expectedAudience = List.of("https://gw.example.com");
        opts.issuerKeys = Map.of("ca-2026-01", caPub);
        opts.principalJwks = Map.of("principal-zhangsan-2026", principalPub);
        opts.presenterKey = principalPub;
        opts.nonceStore = NonceStore.newMemNonceStore();
        Constraints.RequestContext ctx = new Constraints.RequestContext();
        ctx.now = Instant.ofEpochSecond(IAT + 60);
        ctx.sourceIp = InetAddress.getByName("10.1.2.3");
        ctx.concurrentCount = 1;
        opts.requestContext = ctx;
        opts.requestCapability = new Claims.Capability("database", "query:SELECT",
                JwtJson.parse("{\"max_rows\":50}"));
        opts.capabilityPlugins = Map.of("database", (req, c) -> {
            int rows = req.params.path("max_rows").asInt();
            if (rows > 200) {
                throw new AicException("max_rows exceeds budget");
            }
        });

        Validator.Decision d = Validator.validate(OUTER_TOKEN, opts);
        assertTrue(d.permit);
        assertEquals("agent:db-analyst-01", d.actor);
    }

    @Test
    void goTokenFailsWhenConstraintIsViolated() throws Exception {
        PublicKey principalPub = pubKey(PRINCIPAL_SPKI_B64);
        PublicKey caPub = pubKey(CA_SPKI_B64);
        Validator.VerifyOptions opts = new Validator.VerifyOptions();
        opts.now = Instant.ofEpochSecond(IAT + 60);
        opts.issuerKeys = Map.of("ca-2026-01", caPub);
        opts.principalJwks = Map.of("principal-zhangsan-2026", principalPub);
        Constraints.RequestContext ctx = new Constraints.RequestContext();
        ctx.now = Instant.ofEpochSecond(IAT + 60);
        ctx.sourceIp = InetAddress.getByName("192.168.9.9"); // outside 10.0.0.0/8
        opts.requestContext = ctx;
        opts.nonceStore = NonceStore.newMemNonceStore();
        AicException ex = assertThrows(AicException.class, () -> Validator.validate(OUTER_TOKEN, opts));
        assertTrue(ex.getMessage().contains("step7"), ex.getMessage());
    }

    @Test
    void goTokenExpiredRejected() throws Exception {
        PublicKey principalPub = pubKey(PRINCIPAL_SPKI_B64);
        PublicKey caPub = pubKey(CA_SPKI_B64);
        Validator.VerifyOptions opts = new Validator.VerifyOptions();
        opts.now = Instant.ofEpochSecond(IAT + 4000);
        opts.issuerKeys = Map.of("ca-2026-01", caPub);
        opts.principalJwks = Map.of("principal-zhangsan-2026", principalPub);
        opts.requestContext = new Constraints.RequestContext();
        opts.requestContext.now = Instant.ofEpochSecond(IAT + 4000);
        opts.nonceStore = NonceStore.newMemNonceStore();
        AicException ex = assertThrows(AicException.class, () -> Validator.validate(OUTER_TOKEN, opts));
        assertTrue(ex.getMessage().contains("step3"), ex.getMessage());
        assertFalse(ex.getMessage().contains("nonce"));
    }
}