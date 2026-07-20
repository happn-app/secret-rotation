---
title: JWT
tags:
  - crypto
---

Re-signs a [JWT](https://datatracker.ietf.org/doc/html/rfc7519) (JSON Web Token), preserving its claims but refreshing
its validity window.

The secret payload is the current signed JWT. On rotation the handler:

1. Loads the signing JWK from the secret named by the `jwt_rsa__jwk_secret_name` label.
2. Parses the old JWT and computes its TTL (`exp - iat`).
3. Sets new `iat` = now, `exp` = now + TTL, a fresh `jti` (UUIDv7), and `iss` = `secret-rotator`.
4. Signs with the JWK's algorithm (`kid` from the key is added to the header).
5. Stores the new signed JWT as a new secret version.

All other claims from the old token are carried over unchanged.

## Configuration

Set the handler label on the secret:

```txt
<handler_label_key>=jwt
jwt_rsa__jwk_secret_name=<name of the Secret Manager secret holding the JWK>
```

| Label             | Required | Description                                                                                                                                      |
| ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `jwk_secret_name` | yes      | Name of the Secret Manager secret whose latest version holds the JWK Set used to sign the token. Rotate this key with the [JWK](jwk.md) handler. |
