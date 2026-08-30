# AIC SDK for Java — Documentation

Java implementation of the AIC (Authorization in Certificates) family,
covering both RFC drafts. Ported from the Go reference implementation
([`varwof/types`](../../types) / [`varwof/types/aicjwt`](../../types/aicjwt)).

## Profile coverage

| Profile | Draft | Package | Docs |
|---------|-------|---------|------|
| X.509 / ASN.1 | `draft-wei-aic-identity-cert` | `com.varwof.aic` + `com.varwof.aic.cert` | [cert-profile.md](cert-profile.md) |
| JWT | `draft-wei-aic-jwt` | `com.varwof.aic.jwt` | [jwt-profile.md](jwt-profile.md) |
| Cross-language | — | test suite | [conformance.md](conformance.md) |

## Core packages

- `com.varwof.aic` — AIC model (`Aic`, `AicBuilder`), `PrincipalUid`,
  `Capability`, `DelegationAuthTbs`, `DelegationAuthorization`,
  `DelegationAuthCrypto` (sign/verify), `AicValidator` (spec constraints),
  `PrincipalAuthorization`, capability matcher/rules, DER helpers.
- `com.varwof.aic.cert` — X.509 certificate builders and extension
  extraction (`AicCertificateBuilder`, `AicCertificates`).
- `com.varwof.aic.jwt` — AIC-JWT: `Jws`, `Claims`, `CapMatch`, `Constraints`,
  `KeyHash`, `Validator` (11-step pipeline), `NonceStore`.

## Quick reference

| Task | Entry point |
|------|-------------|
| Build an AIC value | `Aic.builder()… .build()` |
| Encode / parse DER | `Aic.encode()` / `Aic.parse(byte[])` |
| Spec validation | `AicValidator.validate(aic)` |
| Sign a DA | `DelegationAuthCrypto.sign(tbs, privateKey)` |
| Verify a DA | `DelegationAuthCrypto.verify(tbs, da, principalPubKey)` |
| Issue principal/agent cert | `AicCertificateBuilder.buildPrincipalCert/buildAgentCert` |
| Extract AIC from cert | `AicCertificates.parseAndValidateAic(cert)` |
| Validate an AIC-JWT | `jwt.Validator.validate(token, opts)` |

## Build & test

```sh
scripts/fetch-deps.sh
scripts/build.sh        # 69/69 tests
# or: mvn test
```

See [README.md](../README.md).
