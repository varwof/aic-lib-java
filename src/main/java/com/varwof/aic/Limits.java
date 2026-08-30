package com.varwof.aic;

/**
 * Hard limits governing AIC policy evaluation and structure.
 * Constants mirror {@code types/limits.go} and the draft recommendations so
 * the Java and C# ports reject identical inputs as the Go reference.
 */
public final class Limits {
    private Limits() {
    }

    public static final int MAX_CAPABILITIES = 256;
    public static final int MAX_AUTHORIZATION_CONSTRAINTS = 32;
    public static final int MAX_EXTENSIONS_SLOTS = 32;
    public static final int MAX_GRANT_ENTRIES = 256;
    public static final int MAX_CONSTRAINT_PARAMS = 512;
    public static final int MAX_CAP_PARAMS = 4096;
    public static final int MAX_NONCE_LEN = 32;
    public static final int MAX_REQUESTED_LIFETIME = 86400;
    public static final int MIN_REQUESTED_LIFETIME = 3600;
    public static final int MAX_RECOMMENDED_CERT_DER_SIZE = 12 * 1024;
}