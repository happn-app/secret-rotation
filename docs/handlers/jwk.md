---
title: JWK
tags:
  - crypto
---

Generates a new [JWK](https://datatracker.ietf.org/doc/html/rfc7517) (JSON Web Key) to replace the rotating secret.

The secret payload is expected to be a JWK Set. The handler reads the first key, then generates a fresh key of the
**same algorithm and key size**, assigns it a new key ID (`kid`), and stores the marshalled key as a new secret version.

## Supported algorithms

| `alg`                       | Key type generated                        |
| --------------------------- | ----------------------------------------- |
| `RS256` / `RS384` / `RS512` | RSA private key                           |
| `PS256` / `PS384` / `PS512` | RSA private key (RSASSA-PSS)              |
| `ES256` / `ES384` / `ES512` | ECDSA private key (P-256 / P-384 / P-521) |
| `HS256` / `HS384` / `HS512` | Symmetric (oct) key                       |
| `EdDSA`                     | Ed25519 private key                       |

Key size is derived from the existing key, so the new key matches the old one's strength.

## Configuration

Set the handler label on the secret:

```txt
<handler_label_key>=jwk
```

No additional labels required.
