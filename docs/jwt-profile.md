# AIC-JWT profile (`draft-wei-aic-jwt`)

JWT profile for the AIC identity model. Implementation: `com.varwof.aic.jwt`.
Mirrors Go `types/aicjwt` step for step, including error-prefixed diagnostics
used for conformance testing.

## Token types

| `typ` | Meaning |
|-------|---------|
| `aic+jwt` | outer token |
| `aic+da+jwt` | DelegationAuthorization token |
| `aic+pa+jwt` | PrincipalAuthorization token |

## Validation pipeline

`Validator.validate(token, opts)` implements the full 11-step pipeline from
the draft (Section 11):

1. Bound the token size (`MAX_TOKEN_SIZE = 64 KiB`).
2. Parse & check the JWS header (`alg`, `typ`, `kid`, `crit`).
3. Verify the JWS signature against the issuer's public key.
4. Decode & validate the claims (`iat`, `exp`, `nbf`, `aud`, `iss`).
5. Validate the embedded principal (`realm`/`id`/`keyHash`) and its SPKI
   key-binding (RFC 7638 JWK thumbprint `cnf.jkt`).
6. Validate delegation mode against the allow-list.
7. Validate capabilities & authorization constraints (schemes fail-closed).
8. Evaluate constraints (e.g. `max-concurrent`) via `Constraints`.
9. Capability matching against request/principal grants via `CapMatch`.
10. Nonce / replay check via `NonceStore` (optional).
11. Return a `Decision` (permit / deny) with actor, principal, permissions.

## Usage

```java
import com.varwof.aic.jwt.*;

Validator.Decision d = Validator.validate(token, new Validator.VerifyOptions()
        .withIssuerKeys(kid -> key)              // JWK Set lookup
        .withExpectedAudience("gateway")
        .withExpectedIssuer("ca.example")
        .withNow(Instant.now()));

if (d.permit()) {
    // d.actor(), d.principal(), d.permissions()
}
```

### Options

| Field | Purpose |
|-------|---------|
| `now` | clock reference for `iat`/`exp`/`nbf` |
| `expectedIssuer` | required `iss` |
| `expectedAudience` | required `aud` |
| `issuerKeys` | `kid` → public key for signature verification |
| `principalJwks` | online principal public keys |
| `capabilityPlugins` | request-capability evaluation (fail-closed for unknown schemes) |
| `statusCheckers` | Token Status List reference checks |
| `nonceStore` | anti-replay (see below) |

## Anti-replay

`NonceStore` tracks seen nonces. Provide a persistent implementation for
cross-process deduplication; the in-memory default is session-scoped. The
protocol's primary freshness guarantee is the CA issuing a nonce challenge
before signing.

## Security limits

- `MAX_TOKEN_SIZE = 64 KiB` — bounds CPU/memory cost of parsing.
- `MAX_PARAMS_SIZE = 512` — max serialized capability params object.
- `MAX_LIFETIME = 86400` — upper bound for requested lifetime.
- Capability schemes are fail-closed: unknown scheme → deny.

## Algorithms

`Jws` supports ES256, RS256, PS256, PS384, PS512 and EdDSA. RSA-PSS uses salt
length equal to the digest. ES384/ES512 and RS384/RS512 are in the JOSE
allowlist but intentionally not implemented (MAY-level).
