package com.varwof.aic.jwt;

import com.varwof.aic.AicException;
import com.varwof.aic.Ecdsa;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.Set;

/**
 * JWS compact serialization primitives (draft-wei-aic-jwt Section 4.5).
 * Mirrors Go {@code types/aicjwt/jws.go}. ECDSA signatures use the JOSE
 * R||S representation while JCA uses DER, so the two are translated.
 */
public final class Jws {
    private Jws() {
    }

    /**
     * Full JOSE algorithm allowlist. ES384, ES512, RS384 and RS512 are
     * MAY-level: a conforming implementation MAY reject them, and this one
     * does.
     */
    public static final Set<String> ALLOWED_ALGS = Set.of(
            "ES256", "ES384", "ES512",
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512", "EdDSA");

    /** Algorithms actually implemented here. */
    public static final Set<String> IMPLEMENTED_ALGS = Set.of(
            "ES256", "RS256", "PS256", "PS384", "PS512", "EdDSA");

    public static String b64uEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] b64uDecode(String s) {
        if (s == null) {
            throw new AicException("bad base64url: nil input");
        }
        if (s.length() % 4 == 1) {
            throw new AicException("bad base64url: invalid length");
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                throw new AicException("bad base64url: invalid character '" + c + "'");
            }
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException ex) {
            throw new AicException("bad base64url: " + ex.getMessage());
        }
    }

    /**
     * Creates a JWS compact serialization. header and payload are raw JSON
     * bytes; the protected header MUST carry alg and typ.
     */
    public static String signCompact(byte[] header, byte[] payload, String alg, PrivateKey key) {
        if (!ALLOWED_ALGS.contains(alg)) {
            throw new AicException("algorithm \"" + alg + "\" not in AIC-JWT allowlist");
        }
        if (!IMPLEMENTED_ALGS.contains(alg)) {
            throw new AicException("algorithm \"" + alg + "\" recognized but not implemented");
        }
        String eh = b64uEncode(header);
        String ep = b64uEncode(payload);
        String signingInput = eh + "." + ep;
        byte[] sig = signBytes(alg, signingInput.getBytes(StandardCharsets.US_ASCII), key);
        return signingInput + "." + b64uEncode(sig);
    }

    /** Splits a JWS compact serialization into header, payload and signature bytes. */
    public static byte[][] parseCompact(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new AicException("malformed JWS compact serialization");
        }
        return new byte[][]{b64uDecode(parts[0]), b64uDecode(parts[1]), b64uDecode(parts[2])};
    }

    /** Verifies the JWS signature for alg over the compact token. */
    public static void verifyCompact(String token, String alg, PublicKey pub) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new AicException("malformed JWS compact serialization");
        }
        byte[] sig = b64uDecode(parts[2]);
        byte[] input = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        try {
            verifyBytes(alg, input, sig, pub);
        } catch (GeneralSecurityException ex) {
            throw new AicException("JWS signature verification failed: " + ex.getMessage());
        }
    }

    private static byte[] signBytes(String alg, byte[] input, PrivateKey key) {
        try {
            switch (alg) {
                case "ES256":
                    return signES(input, key, 256);
                case "RS256":
                    return signPKCS1(input, key, "SHA-256");
                case "PS256":
                    return signPSS(input, key, "SHA-256", 32);
                case "PS384":
                    return signPSS(input, key, "SHA-384", 48);
                case "PS512":
                    return signPSS(input, key, "SHA-512", 64);
                case "EdDSA":
                    Signature ed = Signature.getInstance("Ed25519");
                    ed.initSign(key);
                    ed.update(input);
                    return ed.sign();
                default:
                    throw new AicException("algorithm \"" + alg + "\" not supported");
            }
        } catch (GeneralSecurityException ex) {
            throw new AicException("signing failed: " + ex.getMessage());
        }
    }

    private static byte[] signES(byte[] input, PrivateKey key, int bits) throws GeneralSecurityException {
        if (!(key instanceof ECKey)) {
            throw new AicException("ES256 requires an EC private key");
        }
        int orderBits = ((ECKey) key).getParams().getOrder().bitLength();
        if (orderBits != bits) {
            throw new AicException("ES256 requires a P-256 key");
        }
        Signature sig = Signature.getInstance(curveSigName(bits));
        sig.initSign(key);
        sig.update(input);
        byte[] der = sig.sign();
        return Ecdsa.derToRs(der, bits);
    }

    private static byte[] signPKCS1(byte[] input, PrivateKey key, String md) throws GeneralSecurityException {
        requireRsa(key);
        Signature sig = Signature.getInstance(md.replace("-", "") + "withRSA");
        sig.initSign(key);
        sig.update(input);
        return sig.sign();
    }

    private static byte[] signPSS(byte[] input, PrivateKey key, String md, int salt)
            throws GeneralSecurityException {
        requireRsa(key);
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(pssParam(md, salt));
        sig.initSign(key);
        sig.update(input);
        return sig.sign();
    }

    private static PSSParameterSpec pssParam(String md, int salt) {
        MGF1ParameterSpec mgf;
        switch (md) {
            case "SHA-384":
                mgf = MGF1ParameterSpec.SHA384;
                break;
            case "SHA-512":
                mgf = MGF1ParameterSpec.SHA512;
                break;
            default:
                mgf = MGF1ParameterSpec.SHA256;
                break;
        }
        return new PSSParameterSpec(md, "MGF1", mgf, salt, 1);
    }

    private static void requireRsa(PrivateKey key) {
        if (!(key instanceof RSAKey)) {
            throw new AicException("RSA signature algorithm requires an RSA key");
        }
    }

    private static String curveSigName(int bits) {
        if (bits == 256) {
            return "SHA256withECDSA";
        }
        if (bits == 384) {
            return "SHA384withECDSA";
        }
        return "SHA512withECDSA";
    }

    private static void verifyBytes(String alg, byte[] input, byte[] sig, PublicKey pub)
            throws GeneralSecurityException {
        switch (alg) {
            case "ES256":
                verifyES(input, sig, pub, 256);
                break;
            case "RS256":
                Signature rs = Signature.getInstance("SHA256withRSA");
                rs.initVerify(pub);
                rs.update(input);
                require(rs.verify(sig), "RS256 signature verification failed");
                break;
            case "PS256":
                verifyPSS(input, sig, pub, "SHA-256", 32);
                break;
            case "PS384":
                verifyPSS(input, sig, pub, "SHA-384", 48);
                break;
            case "PS512":
                verifyPSS(input, sig, pub, "SHA-512", 64);
                break;
            case "EdDSA":
                Signature ed = Signature.getInstance("Ed25519");
                ed.initVerify(pub);
                ed.update(input);
                require(ed.verify(sig), "EdDSA signature verification failed");
                break;
            default:
                throw new AicException("algorithm \"" + alg + "\" not supported");
        }
    }

    private static void verifyES(byte[] input, byte[] sig, PublicKey pub, int bits)
            throws GeneralSecurityException {
        int size = Ecdsa.coordBytes(bits);
        if (sig.length != 2 * size) {
            throw new AicException("ES256 signature length mismatch");
        }
        Signature ver = Signature.getInstance(curveSigName(bits));
        ver.initVerify(pub);
        ver.update(input);
        require(ver.verify(Ecdsa.rsToDer(sig, bits)), "ECDSA signature verification failed");
    }

    private static void verifyPSS(byte[] input, byte[] sig, PublicKey pub, String md, int salt)
            throws GeneralSecurityException {
        Signature ver = Signature.getInstance("RSASSA-PSS");
        ver.setParameter(pssParam(md, salt));
        ver.initVerify(pub);
        ver.update(input);
        require(ver.verify(sig), "PSS signature verification failed");
    }

    private static void require(boolean ok, String msg) {
        if (!ok) {
            throw new AicException(msg);
        }
    }
}