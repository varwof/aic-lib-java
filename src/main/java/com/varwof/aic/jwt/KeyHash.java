package com.varwof.aic.jwt;

import com.varwof.aic.AicException;
import com.varwof.aic.HashAlgorithms;
import com.varwof.aic.Oids;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Map;

/**
 * Key material and hash bindings for AIC-JWT (draft-wei-aic-jwt Section 9).
 * Mirrors Go {@code types/aicjwt/keyhash.go}: RFC 7638 JWK thumbprints,
 * SPKI hashes, JWK&lt;-&gt;public conversions and principal key lookup.
 */
public final class KeyHash {
    private KeyHash() {
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** hash_alg values implemented here. sha3-* and sm3 are not implemented. */
    public static final Map<String, Integer> SUPPORTED_HASH_ALGS = Map.of(
            "sha-256", 32, "sha-384", 48, "sha-512", 64, "jkt", 32);

    /** Minimal RFC 7517 public JWK supporting EC, RSA and OKP. */
    public static final class Jwk {
        public String kty;
        public String crv;
        public String x;
        public String y;
        public String n;
        public String e;

        public Jwk() {
        }

        public Jwk(String kty, String crv, String x, String y, String n, String e) {
            this.kty = kty;
            this.crv = crv;
            this.x = x;
            this.y = y;
            this.n = n;
            this.e = e;
        }
    }

    /** Computes hash_alg(SPKI) over an X.509 SubjectPublicKeyInfo DER blob. */
    public static String spkiHash(byte[] spkiDer, String hashAlg) {
        switch (hashAlg) {
            case "sha-256":
                return Jws.b64uEncode(HashAlgorithms.keyHashFromSpki(Oids.SHA256, spkiDer));
            case "sha-384":
                return Jws.b64uEncode(HashAlgorithms.keyHashFromSpki(Oids.SHA384, spkiDer));
            case "sha-512":
                return Jws.b64uEncode(HashAlgorithms.keyHashFromSpki(Oids.SHA512, spkiDer));
            default:
                throw new AicException("unsupported SPKI hash algorithm \"" + hashAlg + "\"");
        }
    }

    /** Computes hash_alg(SPKI) directly from a public key. */
    public static String spkiHashPub(PublicKey pub, String hashAlg) {
        return spkiHash(pub.getEncoded(), hashAlg);
    }

    /** RFC 7638 JWK thumbprint for EC, RSA and OKP keys. */
    public static String jwkThumbprint(Jwk j) {
        String canon;
        switch (j.kty) {
            case "EC":
                canon = "{\"crv\":\"" + j.crv + "\",\"kty\":\"EC\",\"x\":\"" + j.x + "\",\"y\":\"" + j.y + "\"}";
                break;
            case "RSA":
                canon = "{\"e\":\"" + j.e + "\",\"kty\":\"RSA\",\"n\":\"" + j.n + "\"}";
                break;
            case "OKP":
                canon = "{\"crv\":\"" + j.crv + "\",\"kty\":\"OKP\",\"x\":\"" + j.x + "\"}";
                break;
            default:
                throw new AicException("unsupported kty \"" + j.kty + "\"");
        }
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return Jws.b64uEncode(md.digest(canon.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new AicException("SHA-256 unavailable: " + ex.getMessage());
        }
    }

    /** Converts a public key to a minimal JWK. */
    public static Jwk publicKeyToJwk(PublicKey pub) {
        if (pub instanceof ECPublicKey) {
            ECPublicKey k = (ECPublicKey) pub;
            int bits = curveBits(k);
            String crv;
            switch (bits) {
                case 256:
                    crv = "P-256";
                    break;
                case 384:
                    crv = "P-384";
                    break;
                case 521:
                    crv = "P-521";
                    break;
                default:
                    throw new AicException("unsupported curve");
            }
            int size = (bits + 7) / 8;
            byte[] xb = toFixed(k.getW().getAffineX(), size);
            byte[] yb = toFixed(k.getW().getAffineY(), size);
            return new Jwk("EC", crv, Jws.b64uEncode(xb), Jws.b64uEncode(yb), null, null);
        }
        if (pub instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) pub;
            return new Jwk("RSA", null, null, null,
                    Jws.b64uEncode(toMinimal(k.getModulus())),
                    Jws.b64uEncode(toMinimal(k.getPublicExponent())));
        }
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            if (Oids.ED25519.equals(spki.getAlgorithm().getAlgorithm())) {
                byte[] raw = spki.getPublicKeyData().getBytes();
                return new Jwk("OKP", "Ed25519", Jws.b64uEncode(raw), null, null, null);
            }
        } catch (Exception ex) {
            // fall through below
        }
        throw new AicException("unsupported public key type " + pub.getClass().getName());
    }

    /** Converts a minimal JWK back to a public key. */
    public static PublicKey jwkToPublic(Jwk j) {
        try {
            switch (j.kty) {
                case "EC": {
                    String name;
                    switch (j.crv) {
                        case "P-256":
                            name = "secp256r1";
                            break;
                        case "P-384":
                            name = "secp384r1";
                            break;
                        case "P-521":
                            name = "secp521r1";
                            break;
                        default:
                            throw new AicException("unsupported curve \"" + j.crv + "\"");
                    }
                    org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                            ECNamedCurveTable.getParameterSpec(name);
                    ECCurve curve = spec.getCurve();
                    byte[] xb = Jws.b64uDecode(j.x);
                    byte[] yb = Jws.b64uDecode(j.y);
                    org.bouncycastle.math.ec.ECPoint point = curve.createPoint(
                            new BigInteger(1, xb), new BigInteger(1, yb));
                    org.bouncycastle.jce.spec.ECPublicKeySpec keySpec =
                            new org.bouncycastle.jce.spec.ECPublicKeySpec(point, spec);
                    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                    return kf.generatePublic(keySpec);
                }
                case "RSA": {
                    BigInteger n = new BigInteger(1, Jws.b64uDecode(j.n));
                    BigInteger e = new BigInteger(1, Jws.b64uDecode(j.e));
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return kf.generatePublic(new RSAPublicKeySpec(n, e));
                }
                case "OKP": {
                    byte[] xb = Jws.b64uDecode(j.x);
                    if (!"Ed25519".equals(j.crv)) {
                        throw new AicException("unsupported OKP crv \"" + j.crv + "\"");
                    }
                    // rebuild the X.509 SubjectPublicKeyInfo for Ed25519
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                            new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(Oids.ED25519),
                                    new org.bouncycastle.asn1.DERBitString(xb));
                    KeyFactory kf = KeyFactory.getInstance("X.509");
                    return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));
                }
                default:
                    throw new AicException("unsupported kty \"" + j.kty + "\"");
            }
        } catch (AicException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AicException("cannot import JWK: " + ex.getMessage());
        }
    }

    /**
     * Computes the binding of a public key for the given hash_alg: "jkt"
     * uses the RFC 7638 thumbprint, otherwise the SPKI hash.
     */
    public static String keyHashOf(PublicKey pub, String hashAlg) {
        if ("jkt".equals(hashAlg)) {
            return jwkThumbprint(publicKeyToJwk(pub));
        }
        if (hashAlg == null || hashAlg.isEmpty()) {
            hashAlg = "sha-256";
        }
        return spkiHashPub(pub, hashAlg);
    }

    /** Optional credential bundle: X5C certs (PKI mode) or JWKs (pure-JSON). */
    public static final class PrincipalKeyMaterial {
        public List<java.security.cert.X509Certificate> x5c;
        public Map<String, Jwk> jwk;

        public PrincipalKeyMaterial() {
        }

        public PrincipalKeyMaterial(List<java.security.cert.X509Certificate> x5c, Map<String, Jwk> jwk) {
            this.x5c = x5c;
            this.jwk = jwk;
        }

        /** Finds a principal key whose binding matches the principal claim. */
        public PublicKey lookupByBinding(Claims.Principal p) {
            if ("jkt".equals(p.hashAlg)) {
                if (jwk != null) {
                    for (Jwk j : jwk.values()) {
                        if (jwkThumbprint(j).equals(p.keyHash)) {
                            return jwkToPublic(j);
                        }
                    }
                }
                throw new AicException("no JWK matches key_hash " + p.keyHash);
            }
            String alg = p.hashAlg;
            if (alg == null || alg.isEmpty()) {
                alg = "sha-256";
            }
            if (x5c != null) {
                for (java.security.cert.X509Certificate cert : x5c) {
                    try {
                        byte[] spki = cert.getPublicKey().getEncoded();
                        if (spkiHash(spki, alg).equals(p.keyHash)) {
                            return cert.getPublicKey();
                        }
                    } catch (AicException ex) {
                        continue;
                    }
                }
            }
            throw new AicException("no certificate matches key_hash " + p.keyHash);
        }
    }

    /** Decodes a JWK JSON object. */
    public static Jwk parseJwk(byte[] raw) {
        try {
            return JwtJson.MAPPER.readValue(raw, Jwk.class);
        } catch (Exception ex) {
            throw new AicException("invalid JWK: " + ex.getMessage());
        }
    }

    static int curveBits(ECPublicKey k) {
        return k.getParams().getCurve().getField().getFieldSize();
    }

    /** Minimal unsigned big-endian magnitude, matching Go big.Int.Bytes(). */
    private static byte[] toMinimal(BigInteger v) {
        byte[] raw = v.abs().toByteArray();
        int offset = 0;
        while (offset < raw.length - 1 && raw[offset] == 0) {
            offset++;
        }
        byte[] out = new byte[raw.length - offset];
        System.arraycopy(raw, offset, out, 0, out.length);
        return out;
    }

    private static byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        if (raw.length == size) {
            return raw;
        }
        if (raw.length == size + 1 && raw[0] == 0) {
            // strip the sign/guard byte
            byte[] trimmed = new byte[size];
            System.arraycopy(raw, 1, trimmed, 0, size);
            return trimmed;
        }
        byte[] out = new byte[size];
        int src = 0;
        while (src < raw.length - 1 && raw[src] == 0) {
            src++;
        }
        System.arraycopy(raw, src, out, size - (raw.length - src), raw.length - src);
        return out;
    }
}