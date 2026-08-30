package com.varwof.aic;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OID assignments for the Varwof AIC family (IANA PEN 1.3.6.1.4.1.66257).
 * Mirrors the canonical table in the Go reference implementation
 * ({@code types/oid.go}) and draft-wei-aic-identity-cert-00 section 4.1.
 */
public final class Oids {
    private Oids() {
    }

    /** id-varwof : 1.3.6.1.4.1.66257 */
    public static final ASN1ObjectIdentifier VARWOF = new ASN1ObjectIdentifier("1.3.6.1.4.1.66257");

    // ---- AIC extension tree (identity & authorization core) ----
    /** AIC extension OID : 1.3.6.1.4.1.66257.1.1 */
    public static final ASN1ObjectIdentifier AIC = VARWOF.branch("1.1");
    /** AgentIdentity sub-OID : 1.3.6.1.4.1.66257.1.1.1 */
    public static final ASN1ObjectIdentifier AIC_AGENT_IDENTITY = VARWOF.branch("1.1.1");
    /** DelegationAuthorization sub-OID : 1.3.6.1.4.1.66257.1.1.2 */
    public static final ASN1ObjectIdentifier AIC_DELEGATION_AUTHORIZATION = VARWOF.branch("1.1.2");
    /** DelegationDepthControl : 1.3.6.1.4.1.66257.1.1.4 */
    public static final ASN1ObjectIdentifier DELEGATION_DEPTH_CONTROL = VARWOF.branch("1.1.4");
    /** chainDepth : 1.3.6.1.4.1.66257.1.1.4.1 */
    public static final ASN1ObjectIdentifier DDC_CHAIN_DEPTH = VARWOF.branch("1.1.4.1");
    /** maxDepth : 1.3.6.1.4.1.66257.1.1.4.2 */
    public static final ASN1ObjectIdentifier DDC_MAX_DEPTH = VARWOF.branch("1.1.4.2");

    /** PrincipalAuthorization extension OID : 1.3.6.1.4.1.66257.1.2 */
    public static final ASN1ObjectIdentifier PRINCIPAL_AUTHORIZATION = VARWOF.branch("1.2");
    /** Capability scheme registry (reserved) : 1.3.6.1.4.1.66257.1.3 */
    public static final ASN1ObjectIdentifier CAPABILITY_SCHEME_REGISTRY = VARWOF.branch("1.3");
    /** Vendor extension registry (reserved) : 1.3.6.1.4.1.66257.1.4 */
    public static final ASN1ObjectIdentifier VENDOR_EXTENSION_REGISTRY = VARWOF.branch("1.4");
    /** Renewal token : 1.3.6.1.4.1.66257.1.6 */
    public static final ASN1ObjectIdentifier RENEWAL_TOKEN = VARWOF.branch("1.6");

    // ---- 3.x certification extensions ----
    /** 1.3.6.1.4.1.66257.3.1 */
    public static final ASN1ObjectIdentifier MARKET_ACCESS_ID = VARWOF.branch("3.1");
    /** 1.3.6.1.4.1.66257.3.2 */
    public static final ASN1ObjectIdentifier TRUST_LEVEL = VARWOF.branch("3.2");
    /** 1.3.6.1.4.1.66257.3.3 */
    public static final ASN1ObjectIdentifier CROSS_BORDER = VARWOF.branch("3.3");

    // ---- Signature algorithm OIDs ----
    /** 1.2.840.10045.4.3.2 ecdsa-with-SHA256 */
    public static final ASN1ObjectIdentifier ECDSA_WITH_SHA256 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
    /** 1.2.840.10045.4.3.3 ecdsa-with-SHA384 */
    public static final ASN1ObjectIdentifier ECDSA_WITH_SHA384 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
    /** 1.2.840.10045.4.3.4 ecdsa-with-SHA512 */
    public static final ASN1ObjectIdentifier ECDSA_WITH_SHA512 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.4");
    /** 1.2.840.113549.1.1.11 sha256WithRSAEncryption */
    public static final ASN1ObjectIdentifier RSA_WITH_SHA256 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
    /** 1.2.840.113549.1.1.12 sha384WithRSAEncryption */
    public static final ASN1ObjectIdentifier RSA_WITH_SHA384 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.12");
    /** 1.2.840.113549.1.1.13 sha512WithRSAEncryption */
    public static final ASN1ObjectIdentifier RSA_WITH_SHA512 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.13");
    /** 1.2.840.113549.1.1.10 RSASSA-PSS */
    public static final ASN1ObjectIdentifier RSA_PSS = new ASN1ObjectIdentifier("1.2.840.113549.1.1.10");
    /** 1.3.101.112 Ed25519 */
    public static final ASN1ObjectIdentifier ED25519 = new ASN1ObjectIdentifier("1.3.101.112");

    // ---- Hash algorithm OIDs ----
    /** 2.16.840.1.101.3.4.2.1 SHA-256 */
    public static final ASN1ObjectIdentifier SHA256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
    /** 2.16.840.1.101.3.4.2.2 SHA-384 */
    public static final ASN1ObjectIdentifier SHA384 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
    /** 2.16.840.1.101.3.4.2.3 SHA-512 */
    public static final ASN1ObjectIdentifier SHA512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
    /** 2.16.840.1.101.3.4.2.8 SHA3-256 */
    public static final ASN1ObjectIdentifier SHA3_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.8");
    /** 2.16.840.1.101.3.4.2.9 SHA3-384 */
    public static final ASN1ObjectIdentifier SHA3_384 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.9");
    /** 2.16.840.1.101.3.4.2.10 SHA3-512 */
    public static final ASN1ObjectIdentifier SHA3_512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.10");
    /** 1.2.156.10197.1.401 SM3 */
    public static final ASN1ObjectIdentifier SM3 = new ASN1ObjectIdentifier("1.2.156.10197.1.401");
}