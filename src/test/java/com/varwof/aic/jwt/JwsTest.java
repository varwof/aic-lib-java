package com.varwof.aic.jwt;

import com.varwof.aic.AicException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JWS compact serialization round trips and tamper rejection for every
 * implemented algorithm.
 */
class JwsTest {

    private static final byte[] HEADER = "{\"alg\":\"ES256\",\"typ\":\"aic+jwt\"}".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PAYLOAD = "{\"sub\":\"agent-109\"}".getBytes(StandardCharsets.US_ASCII);

    private static KeyPair ec(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    private static KeyPair ed() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        return g.generateKeyPair();
    }

    private void roundTrip(String alg, KeyPair kp) {
        String t = Jws.signCompact(HEADER, PAYLOAD, alg, kp.getPrivate());
        byte[][] parts = Jws.parseCompact(t);
        assertArrayEquals(HEADER, parts[0]);
        assertArrayEquals(PAYLOAD, parts[1]);
        Jws.verifyCompact(t, alg, kp.getPublic());
        // tampered signature must fail verification
        assertThrows(AicException.class, () -> Jws.verifyCompact(t + "x", alg, kp.getPublic()));
    }

    @Test
    void es256() {
        roundTrip("ES256", ecKey(256));
    }

    @Test
    void rs256() {
        roundTrip("RS256", rsaKey(2048));
    }

    @Test
    void ps256() {
        roundTrip("PS256", rsaKey(2048));
    }

    @Test
    void ps384() {
        roundTrip("PS384", rsaKey(2048));
    }

    @Test
    void ps512() {
        roundTrip("PS512", rsaKey(2048));
    }

    @Test
    void edDsa() {
        roundTrip("EdDSA", edKey());
    }

    @Test
    void b64uRoundTrip() {
        byte[] raw = {0, 1, 2, 3, -1, 12, 64, 65, 66};
        assertArrayEquals(raw, Jws.b64uDecode(Jws.b64uEncode(raw)));
        assertThrows(AicException.class, () -> Jws.b64uDecode("not*valid!"));
    }

    @Test
    void notInAllowlistRejected() throws Exception {
        KeyPair kp = ecKey(256);
        assertThrows(AicException.class, () -> Jws.signCompact(HEADER, PAYLOAD, "HS256", kp.getPrivate()));
        assertThrows(AicException.class, () -> Jws.signCompact(HEADER, PAYLOAD, "ES384", kp.getPrivate()));
    }

    @Test
    void malformedCompactRejected() {
        assertThrows(AicException.class, () -> Jws.parseCompact("a.b"));
        assertThrows(AicException.class, () -> Jws.parseCompact("a.b.c.d"));
    }

    private static KeyPair ecKey(int bits) {
        try {
            return ec(bits);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static KeyPair rsaKey(int bits) {
        try {
            return rsa(bits);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static KeyPair edKey() {
        try {
            return ed();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}