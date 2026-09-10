package com.varwof.aic.jwt;

import com.varwof.aic.AicException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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

    // Regenerated from the Go reference implementation (draft -01).  The
    // tokens are signed by the keys implied by the SPKI blobs below
    // (principal = presenter key, CA = issuer key) and carry a ver=2 DA.
    private static final String AUTH_OUTER_TOKEN =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNhLTIwMjYtMDEiLCJ0eXAiOiJhaWMrand0In0.eyJpc3MiOiJodHRwczovL2NhLmV4YW1wbGUuY29tL2FpYyIsInN1YiI6ImFnZW50OmRiLWFuYWx5c3QtMDEiLCJhdWQiOlsiaHR0cHM6Ly9ndy5leGFtcGxlLmNvbSJdLCJpYXQiOjE3NTU1MDAwMDAsImV4cCI6MTc1NTUwMzYwMCwianRpIjoiWmsxSXUxUVc0dGhpN2ZpckN5eGUzUmhPaWR3b04wdHdjVndVQUV6Q0ctMCIsImNuZiI6eyJqa3QiOiJqYldyZ3VSU3pLYjFDUFdpSUNIeFF4d3hxREUwdmlFY1ZPYzIybGFTWG4wIn0sImFpYyI6eyJ2ZXIiOjEsInByaW5jaXBhbCI6eyJyZWFsbSI6ImNvcnAuY29tIiwiaWQiOiJ6aGFuZ3NhbiIsImtleV9oYXNoIjoiQXpJNWczT1VFVDhqc3NtWUVZZ2xhMGo2c285WEFxTmU5WXhUdWJ5aVhBRSIsImhhc2hfYWxnIjoic2hhLTI1NiJ9LCJkZWxlZ2F0aW9uX21vZGUiOiJhdXRob3JpemVkIiwiY2FwYWJpbGl0aWVzIjpbeyJzY2hlbWUiOiJkYXRhYmFzZSIsImlkIjoicXVlcnk6U0VMRUNUIiwicGFyYW1zIjp7Im1heF9yb3dzIjoxMDB9fV0sImNvbnN0cmFpbnRzIjpbeyJzY2hlbWUiOiJ2YXJ3b2YvY29uc3RyYWludC12MSIsImlkIjoiYWxsb3dlZC1jaWRyIiwicGFyYW1zIjpbIjEwLjAuMC4wLzgiXX1dLCJtYXhfZGVwdGgiOjF9LCJkYSI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbkJ5YVc1amFYQmhiQzE2YUdGdVozTmhiaTB5TURJMklpd2lkSGx3SWpvaVlXbGpLMlJoSzJwM2RDSjkuZXlKMlpYSWlPaklzSW1semN5STZJbU52Y25BdVkyOXRPbnBvWVc1bmMyRnVJaXdpYzNWaUlqb2lZV2RsYm5RNlpHSXRZVzVoYkhsemRDMHdNU0lzSW1GMVpDSTZXeUpvZEhSd2N6b3ZMMk5oTG1WNFlXMXdiR1V1WTI5dEwyRnBZeUpkTENKbGVIQWlPakUzTlRVMU1ETTJNREFzSW1saGRDSTZNVGMxTlRVd01EQXdNQ3dpYW5ScElqb2lXbXN4U1hVeFVWYzBkR2hwTjJacGNrTjVlR1V6VW1oUGFXUjNiMDR3ZEhkalZuZFZRVVY2UTBjdE1DSXNJbUZuWlc1MFgybGtJam9pWVdkbGJuUTZaR0l0WVc1aGJIbHpkQzB3TVNJc0luQnlhVzVqYVhCaGJDSTZleUp5WldGc2JTSTZJbU52Y25BdVkyOXRJaXdpYVdRaU9pSjZhR0Z1WjNOaGJpSXNJbXRsZVY5b1lYTm9Jam9pUVhwSk5XY3pUMVZGVkRocWMzTnRXVVZaWjJ4aE1HbzJjMjg1V0VGeFRtVTVXWGhVZFdKNWFWaEJSU0lzSW1oaGMyaGZZV3huSWpvaWMyaGhMVEkxTmlKOUxDSnlaV0Z6YjI0aU9uc2lZMjlrWlNJNklrUkJWRUZmUVU1QlRGbFRTVk1pTENKa1pYTmpJam9pVTJOb1pXUjFiR1ZrSUhCeWIyUjFZM1JwYjI0Z1pHRjBZU0JoYm1Gc2VYTnBjeUIzYVc1a2IzY2lmU3dpWTJGd1lXSnBiR2wwYVdWeklqcGJleUp6WTJobGJXVWlPaUprWVhSaFltRnpaU0lzSW1sa0lqb2ljWFZsY25rNlUwVk1SVU5VSWl3aWNHRnlZVzF6SWpwN0ltMWhlRjl5YjNkeklqb3hNREI5ZlYwc0ltUmxiR1ZuWVhScGIyNWZiVzlrWlNJNkltRjFkR2h2Y21sNlpXUWlMQ0pqYjI1emRISmhhVzUwY3lJNlczc2ljMk5vWlcxbElqb2lkbUZ5ZDI5bUwyTnZibk4wY21GcGJuUXRkakVpTENKcFpDSTZJbUZzYkc5M1pXUXRZMmxrY2lJc0luQmhjbUZ0Y3lJNld5SXhNQzR3TGpBdU1DODRJbDE5WFN3aWNtVnhkV1Z6ZEdWa1gyeHBabVYwYVcxbElqb3pOakF3TENKMGN5STZNVGMxTlRVd01EQXdNQ3dpYm05dVkyVWlPaUphYXpGSmRURlJWelIwYUdrM1ptbHlRM2w0WlROU2FFOXBaSGR2VGpCMGQyTldkMVZCUlhwRFJ5MHdJbjAubFpnamhwSUlwaVRGSDZxNVpvVG9KYVFaQXh2c2g5TzhUbDdYRjRQTDhRUzh0U3BsclNySWJvbkxNVnNVVllXNjhsWTlMb3VsUXRHRGdFdWdvY285X1EifQ.ACDOaBMesVNL4AUhHvkULZ4-1PU0jFyd581poY9HfDxlJ_yCivN2WYABh9CxYNpO6NGyw66fv50Re9Ih370XXw";
    private static final String REP_OUTER_TOKEN =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNhLTIwMjYtMDEiLCJ0eXAiOiJhaWMrand0In0.eyJpc3MiOiJodHRwczovL2NhLmV4YW1wbGUuY29tL2FpYyIsInN1YiI6ImNvcnAuY29tOnpoYW5nc2FuIiwiYXVkIjpbImh0dHBzOi8vZ3cuZXhhbXBsZS5jb20iXSwiaWF0IjoxNzU1NTAwMDAwLCJleHAiOjE3NTU1MDM2MDAsImp0aSI6ImZRMVdiTjhZUndScjdoOE9UdkFIZEpLaUlDX2FITjBTREdkZExJRmMzZmsiLCJjbmYiOnsiamt0IjoiamJXcmd1UlN6S2IxQ1BXaUlDSHhReHd4cURFMHZpRWNWT2MyMmxhU1huMCJ9LCJhaWMiOnsidmVyIjoxLCJwcmluY2lwYWwiOnsicmVhbG0iOiJjb3JwLmNvbSIsImlkIjoiemhhbmdzYW4iLCJrZXlfaGFzaCI6IkF6STVnM09VRVQ4anNzbVlFWWdsYTBqNnNvOVhBcU5lOVl4VHVieWlYQUUiLCJoYXNoX2FsZyI6InNoYS0yNTYifSwiZGVsZWdhdGlvbl9tb2RlIjoicmVwcmVzZW50YXRpdmUiLCJjYXBhYmlsaXRpZXMiOlt7InNjaGVtZSI6ImRhdGFiYXNlIiwiaWQiOiJxdWVyeTpTRUxFQ1QiLCJwYXJhbXMiOnsibWF4X3Jvd3MiOjEwMH19XSwiY29uc3RyYWludHMiOlt7InNjaGVtZSI6InZhcndvZi9jb25zdHJhaW50LXYxIiwiaWQiOiJhbGxvd2VkLWNpZHIiLCJwYXJhbXMiOlsiMTAuMC4wLjAvOCJdfV0sIm1heF9kZXB0aCI6MX0sImRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXRwWkNJNkluQnlhVzVqYVhCaGJDMTZhR0Z1WjNOaGJpMHlNREkySWl3aWRIbHdJam9pWVdsaksyUmhLMnAzZENKOS5leUoyWlhJaU9qSXNJbWx6Y3lJNkltTnZjbkF1WTI5dE9ucG9ZVzVuYzJGdUlpd2ljM1ZpSWpvaVkyOXljQzVqYjIwNmVtaGhibWR6WVc0aUxDSmhkV1FpT2xzaWFIUjBjSE02THk5allTNWxlR0Z0Y0d4bExtTnZiUzloYVdNaVhTd2laWGh3SWpveE56VTFOVEF6TmpBd0xDSnBZWFFpT2pFM05UVTFNREF3TURBc0ltcDBhU0k2SW1aUk1WZGlUamhaVW5kU2NqZG9PRTlVZGtGSVpFcExhVWxEWDJGSVRqQlRSRWRrWkV4SlJtTXpabXNpTENKaFoyVnVkRjlwWkNJNkltRm5aVzUwT21SaUxXRnVZV3g1YzNRdE1ERWlMQ0p3Y21sdVkybHdZV3dpT25zaWNtVmhiRzBpT2lKamIzSndMbU52YlNJc0ltbGtJam9pZW1oaGJtZHpZVzRpTENKclpYbGZhR0Z6YUNJNklrRjZTVFZuTTA5VlJWUTRhbk56YlZsRldXZHNZVEJxTm5Odk9WaEJjVTVsT1ZsNFZIVmllV2xZUVVVaUxDSm9ZWE5vWDJGc1p5STZJbk5vWVMweU5UWWlmU3dpY21WaGMyOXVJanA3SW1OdlpHVWlPaUpFUVZSQlgwRk9RVXhaVTBsVElpd2laR1Z6WXlJNklsTmphR1ZrZFd4bFpDQndjbTlrZFdOMGFXOXVJR1JoZEdFZ1lXNWhiSGx6YVhNZ2QybHVaRzkzSW4wc0ltTmhjR0ZpYVd4cGRHbGxjeUk2VzNzaWMyTm9aVzFsSWpvaVpHRjBZV0poYzJVaUxDSnBaQ0k2SW5GMVpYSjVPbE5GVEVWRFZDSXNJbkJoY21GdGN5STZleUp0WVhoZmNtOTNjeUk2TVRBd2ZYMWRMQ0prWld4bFoyRjBhVzl1WDIxdlpHVWlPaUp5WlhCeVpYTmxiblJoZEdsMlpTSXNJbU52Ym5OMGNtRnBiblJ6SWpwYmV5SnpZMmhsYldVaU9pSjJZWEozYjJZdlkyOXVjM1J5WVdsdWRDMTJNU0lzSW1sa0lqb2lZV3hzYjNkbFpDMWphV1J5SWl3aWNHRnlZVzF6SWpwYklqRXdMakF1TUM0d0x6Z2lYWDFkTENKeVpYRjFaWE4wWldSZmJHbG1aWFJwYldVaU9qTTJNREFzSW5Seklqb3hOelUxTlRBd01EQXdMQ0p1YjI1alpTSTZJbVpSTVZkaVRqaFpVbmRTY2pkb09FOVVka0ZJWkVwTGFVbERYMkZJVGpCVFJFZGtaRXhKUm1Nelptc2lmUS43WkRIQTk4SmE3eldFaGlneVhhTXZMNUFKVUd3Qk00RmxwS1g2N1o4bHZSeE51SjdJNUtHWmIzQUxqaXpvYjJSeEV2a0hxZnhqOUNLNl9TRlpTeGVTQSIsImFjdCI6eyJzdWIiOiJhZ2VudDpkYi1hbmFseXN0LTAxIn19.0zhqLA8KHmC7Gsztl8DgDl3uL21d-qFd1TsfPHN4keB_l1gRgy9cotVxJs3DzT2EzTd3MJ5mKHvNdrdmPex2lg";
    private static final String PRINCIPAL_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE44H9QvDhhiXgJ9P1JuZ6TQUHDTi0OHLvQxsM0J1QzTwi1PYliVWFEGIJJZasyRMPBeBHbb9i4W7ZngTyneoW4A==";
    private static final String CA_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6vKjwdHjnm9HxgfEk7O8rYF0gTnjzzfN1TniPM1DSMoKXRqTGP26bx8vN27hTf8X76M+fdyBrTCh+yL/72lyiQ==";
    private static final String EXPECTED_KEY_HASH = "AzI5g3OUET8jssmYEYgla0j6so9XAqNe9YxTubyiXAE";
    private static final String EXPECTED_JKT = "jbWrguRSzKb1CPWiICHxQxwxqDE0viEcVOc22laSXn0";

    @BeforeAll
    static void ensureX509KeyFactory() {
        // JDK 17+ SUN provider no longer registers "X.509" as a KeyFactory
        // algorithm name (it provides DSA/RSA/EC/Ed25519 instead). If the
        // default provider cannot serve X509EncodedKeySpec, register BC once.
        try {
            KeyFactory.getInstance("X.509");
        } catch (NoSuchAlgorithmException e) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

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

        Validator.Decision d = Validator.validate(AUTH_OUTER_TOKEN, opts);
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
        AicException ex = assertThrows(AicException.class, () -> Validator.validate(AUTH_OUTER_TOKEN, opts));
        assertTrue(ex.getMessage().contains("step7"), ex.getMessage());
    }

    /** Representative-mode conformance: RepOuter validates end-to-end and
     * the decision reports the resource owner as actor and the agent
     * (outer.act.sub) as executor. */
    @Test
    void goRepresentativeTokenValidatesEndToEnd() throws Exception {
        PublicKey principalPub = pubKey(PRINCIPAL_SPKI_B64);
        PublicKey caPub = pubKey(CA_SPKI_B64);

        // the presenter key binding (cnf.jkt) and SPKI hash agree with Go
        assertEquals(EXPECTED_KEY_HASH, KeyHash.spkiHashPub(principalPub, "sha-256"));
        assertEquals(EXPECTED_JKT, KeyHash.keyHashOf(principalPub, "jkt"));

        Claims.PaClaims pa = new Claims.PaClaims();
        pa.ver = 1;
        pa.principal = new Claims.Principal("corp.com", "zhangsan",
                EXPECTED_KEY_HASH, "sha-256");
        pa.grants = List.of(
                new Claims.Capability("database", "query:*",
                        JwtJson.parse("{\"max_rows\":1000}")),
                new Claims.Capability("database", "admin:reset"));
        pa.delegationPolicy = new Claims.DelegationPolicy(1,
                Validator.ALLOWED_MODE_REPRESENTATIVE);

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
        opts.pa = pa;

        Validator.Decision d = Validator.validate(REP_OUTER_TOKEN, opts);
        assertTrue(d.permit);
        // representative mode: actor is the resource owner, executor the agent
        assertEquals("zhangsan", d.actor);
        assertEquals("agent:db-analyst-01", d.executor);
        assertEquals("zhangsan", d.principal);
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
        AicException ex = assertThrows(AicException.class, () -> Validator.validate(AUTH_OUTER_TOKEN, opts));
        assertTrue(ex.getMessage().contains("step3"), ex.getMessage());
        assertFalse(ex.getMessage().contains("nonce"));
    }
}