package com.varwof.aic;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static com.varwof.aic.TestHex.decodeHex;
import static com.varwof.aic.TestHex.encodeHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Byte-for-byte DER compatibility with the Go reference implementation.
 * The expected hex strings are produced by
 * {@code encoding/asn1.Marshal(...)} in {@code /tmp/govec3/main.go}.
 */
class DerVectorsTest {

    private static final String AIC_SIMPLE
            = "306f0201010c096167656e742d31303930390201010c08636f72702e636f6d0c087a68616e6773616e0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "3021301f0c04687474700c114745543a2f6170692f76312f7573657273a00404020102020100";

    private static final String AIC_FULL
            = "308201750201010c096167656e742d31303930480201010c08636f72702e636f6d0c087a68616e6773616e0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "a00d300b0609608648016503040201"
            + "3031301f0c04687474700c114745543a2f6170692f76312f7573657273a00404020102300e0c0264620c0853454c4543543a2a"
            + "020100"
            + "a03a303830360c14766172776f662f636f6e73747261696e742d76310c0c616c6c6f7765642d63696472a010040e5b2231302e302e302e302f38225d"
            + "3081a8301b0c04687474700c134e65656420746f20717565727920757365727302020e10180f32303236303831383030303030305a"
            + "0420a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            + "300a06082a8648ce3d040302"
            + "0446202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465";

    private static final String TBS
            = "3082011e0201010c096167656e742d31303930480201010c08636f72702e636f6d0c087a68616e6773616e0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "a00d300b0609608648016503040201"
            + "301b0c04687474700c134e65656420746f207175657279207573657273"
            + "3031301f0c04687474700c114745543a2f6170692f76312f7573657273a00404020102300e0c0264620c0853454c4543543a2a"
            + "020100"
            + "a03a303830360c14766172776f662f636f6e73747261696e742d76310c0c616c6c6f7765642d63696472a010040e5b2231302e302e302e302f38225d"
            + "02020e10"
            + "180f32303236303831383030303030305a"
            + "0420a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

    private static final String PA
            = "3077020101"
            + "302930180c0864617461626173650c0c71756572793a53454c454354300d0c04687474700c054745543a2a"
            + "a03a303830360c14766172776f662f636f6e73747261696e742d76310c0c616c6c6f7765642d63696472a010040e5b2231302e302e302e302f38225d"
            + "a10b3009020101020108020101";

    private static final String CAP
            = "301f0c04687474700c114745543a2f6170692f76312f7573657273a00404020102";

    private static final String PU_FULL
            = "30480201010c08636f72702e636f6d0c087a68616e6773616e0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "a00d300b0609608648016503040201";

    private static final String PU_SIMPLE
            = "30390201010c08636f72702e636f6d0c087a68616e6773616e0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    private static final String DPOL = "3009020101020108020101";

    private static final String DA_RAW
            = "3081a8301b0c04687474700c134e65656420746f20717565727920757365727302020e10"
            + "180f32303236303831383030303030305a"
            + "0420a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            + "300a06082a8648ce3d040302"
            + "0446202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465";

    private static final String EXT_FIELD = "3013060a2b0601040184855103010101000402dead";

    private static byte[] keyHash() {
        return keyHash(0x00);
    }

    private static byte[] keyHash(int start) {
        byte[] k = new byte[32];
        for (int i = 0; i < k.length; i++) {
            k[i] = (byte) (start + i);
        }
        return k;
    }

    private static byte[] nonce() {
        byte[] n = new byte[32];
        for (int i = 0; i < n.length; i++) {
            n[i] = (byte) (0xa0 + i);
        }
        return n;
    }

    private static byte[] sigValue() {
        byte[] s = new byte[70];
        for (int i = 0; i < s.length; i++) {
            s[i] = (byte) (0x20 + i);
        }
        return s;
    }

    private static Instant TS = Instant.parse("2026-08-18T00:00:00Z");

    private static Aic simpleAic() {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(), null);
        Capability cap = new Capability("http", "GET:/api/v1/users", new byte[]{0x01, 0x02});
        return new Aic(1, "agent-109", pu, List.of(cap), DelegationMode.AUTHORIZED, List.of(), null, List.of());
    }

    private static Aic fullAic() {
        PrincipalUid pu = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(),
                new AlgorithmIdentifier(Oids.SHA256));
        Capability http = new Capability("http", "GET:/api/v1/users", new byte[]{0x01, 0x02});
        Capability db = new Capability("db", "SELECT:*");
        Capability cidr = new Capability("varwof/constraint-v1", "allowed-cidr",
                "[\"10.0.0.0/8\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        DelegationAuthorization da = new DelegationAuthorization(
                new Reason("http", "Need to query users"), 3600, TS, nonce(),
                new AlgorithmIdentifier(Oids.ECDSA_WITH_SHA256), sigValue());
        return new Aic(1, "agent-109", pu, List.of(http, db), DelegationMode.AUTHORIZED,
                List.of(cidr), da, List.of());
    }

    @Test
    void aicSimpleMatchesGo() {
        assertEquals(AIC_SIMPLE, encodeHex(simpleAic().encode()));
    }

    @Test
    void aicFullMatchesGo() {
        assertEquals(AIC_FULL, encodeHex(fullAic().encode()));
    }

    @Test
    void tbsMatchesGo() {
        Aic aic = fullAic();
        assertEquals(TBS, encodeHex(DelegationAuthTbs.fromAic(aic).encode()));
    }

    @Test
    void paMatchesGo() {
        Capability cidr = new Capability("varwof/constraint-v1", "allowed-cidr",
                "[\"10.0.0.0/8\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        PrincipalAuthorization pa = new PrincipalAuthorization(1,
                List.of(new Capability("database", "query:SELECT"), new Capability("http", "GET:*")),
                List.of(cidr),
                new DelegationPolicy(1, 8, 1, null), List.of());
        assertEquals(PA, encodeHex(pa.encode()));
    }

    @Test
    void capabilityMatchesGo() {
        assertEquals(CAP, encodeHex(new Capability("http", "GET:/api/v1/users", new byte[]{0x01, 0x02}).encode()));
    }

    @Test
    void principalUidMatchesGo() {
        PrincipalUid full = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(),
                new AlgorithmIdentifier(Oids.SHA256));
        assertEquals(PU_FULL, encodeHex(full.encode()));
        PrincipalUid simple = new PrincipalUid(1, "corp.com", "zhangsan", keyHash(), null);
        assertEquals(PU_SIMPLE, encodeHex(simple.encode()));
    }

    @Test
    void delegationPolicyMatchesGo() {
        assertEquals(DPOL, encodeHex(new DelegationPolicy(1, 8, 1, null).encode()));
    }

    @Test
    void daRawMatchesGo() {
        DelegationAuthorization da = new DelegationAuthorization(
                new Reason("http", "Need to query users"), 3600, TS, nonce(),
                new AlgorithmIdentifier(Oids.ECDSA_WITH_SHA256), sigValue());
        assertEquals(DA_RAW, encodeHex(da.encode()));
    }

    @Test
    void extFieldMatchesGo() {
        ExtField ext = new ExtField(Oids.MARKET_ACCESS_ID, false, new byte[]{(byte) 0xde, (byte) 0xad});
        assertEquals(EXT_FIELD, encodeHex(ext.encode()));
    }

    @Test
    void decodeThenReencodeIsByteStable() {
        Aic a = Aic.parse(decodeHex(AIC_FULL));
        assertEquals(AIC_FULL, encodeHex(a.encode()));
        assertTrue(a.delegationAuthorization().isPresent());

        Aic s = Aic.parse(decodeHex(AIC_SIMPLE));
        assertEquals(AIC_SIMPLE, encodeHex(s.encode()));

        DelegationAuthTbs t = DelegationAuthTbs.parse(decodeHex(TBS));
        assertEquals(TBS, encodeHex(t.encode()));

        PrincipalAuthorization pa = PrincipalAuthorization.parse(decodeHex(PA));
        assertEquals(PA, encodeHex(pa.encode()));
    }
}