# X.509 / ASN.1 profile (`draft-wei-aic-identity-cert`)

This profile embeds AIC into X.509v3 certificate extensions. Implementation:
`com.varwof.aic` (models) + `com.varwof.aic.cert` (certificates).

## OIDs

IANA PEN `1.3.6.1.4.1.66257`. Canonical table in `Oids` (mirrors
`types/oid.go`):

| Constant | OID |
|----------|-----|
| `Oids.AIC` | `1.3.6.1.4.1.66257.1.1` |
| `Oids.AIC_AGENT_IDENTITY` | `1.3.6.1.4.1.66257.1.1.1` |
| `Oids.AIC_DELEGATION_AUTHORIZATION` | `1.3.6.1.4.1.66257.1.1.2` |
| `Oids.DELEGATION_DEPTH_CONTROL` | `1.3.6.1.4.1.66257.1.1.4` |
| `Oids.PRINCIPAL_AUTHORIZATION` | `1.3.6.1.4.1.66257.1.2` |

## AIC extension value

```
SEQUENCE {
  INTEGER version                     (DEFAULT 1)
  UTF8String agentId
  PrincipalUid principalUid
  SEQUENCE OF Capability capabilities
  INTEGER delegationMode              (DEFAULT 0)
  [0] EXPLICIT SEQUENCE OF Capability authorizationConstraints OPTIONAL
  DelegationAuthorization delegationAuthorization OPTIONAL   (required by spec)
  [1] EXPLICIT SEQUENCE OF ExtField extensions OPTIONAL
}
```

### PrincipalUid

```
SEQUENCE {
  INTEGER version                          (DEFAULT 1)
  UTF8String realm                         (1..128)
  UTF8String identifier                    (1..256)
  OCTET STRING keyHash                     (1..64)
  [0] EXPLICIT AlgorithmIdentifier hashAlgo OPTIONAL   -- absent = SHA-256
}
```

Communication format: `{realm}:{identifier}:{keyFingerprint}`, where
`keyFingerprint = base64url(raw, no padding)` of `keyHash`.

### Capability

```
SEQUENCE {
  UTF8String schemeId
  UTF8String capabilityId
  [0] EXPLICIT OCTET STRING parameters OPTIONAL   -- opaque bytes
}
```

Full permission identifier: `schemeId + ":" + capabilityId` (`fullId()`).

### DelegationAuthorization

```
SEQUENCE {
  Reason reason
  INTEGER requestedLifetime              (DEFAULT 0; 1..86400, 0 → 3600)
  GeneralizedTime timestamp
  OCTET STRING nonce                     (32)
  AlgorithmIdentifier signatureAlgorithm
  OCTET STRING signatureValue
}
```

`Reason` is `SEQUENCE { UTF8String reasonCode, UTF8String description }` —
both REQUIRED non-empty (audit/display only).

## DelegationAuthTBS (DA signature input)

Field order is fixed and matches the Go reference exactly:

```
version, agentId, principalUid, reason, capabilities, delegationMode,
authorizationConstraints, requestedLifetime, timestamp, nonce
```

The signature input is the DER encoding of the TBS; the signature
`AlgorithmIdentifier` is recorded inside the DA so verification is
self-describing.

## Signing & verification

```java
DelegationAuthTbs tbs = new DelegationAuthTbs(
        1, "agent-7", pu, reason, caps, mode, constraints,
        3600, Instant.now(), nonce32);

DelegationAuthorization da =
        DelegationAuthCrypto.sign(tbs, principalPrivateKey);
boolean ok = DelegationAuthCrypto.verify(tbs, da, principalPublicKey);
```

Signature algorithms (see `SigAlgorithms`):

| OID | JCA name | Notes |
|-----|----------|-------|
| `ecdsa-with-SHA256/384/512` | `SHA256withECDSA` etc. | DER-encoded signatures |
| `sha256WithRSAEncryption` etc. | `SHA256withRSA` etc. | RSA PKCS#1 |
| `RSASSA-PSS` | `SHA256withRSAandMGF1` | salt len = digest |
| `Ed25519` | `Ed25519` | raw |

Unsupported OIDs → `AicException`.

## Certificates

```java
X509CertificateHolder principalCert = AicCertificateBuilder.buildPrincipalCert(
        issuerKey, subjectKey, principalAuthorization, ...);
X509CertificateHolder agentCert = AicCertificateBuilder.buildAgentCert(
        issuerKey, subjectKey, aic, ...);

// extraction + spec validation
Aic aic = AicCertificates.parseAndValidateAic(agentCert);
PrincipalAuthorization pa =
        AicCertificates.parseAndValidatePrincipalAuthorization(principalCert);
```

`AicCertificateBuilder` also provides `contentSignerFor(key)`,
`principalAuthorizationExtension(pa, critical)`, `aicExtension(aic, critical)`,
and `publicKeyInfo(key)` (SPKI as Go's PKIX marshal).
