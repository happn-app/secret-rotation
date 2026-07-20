---
title: Gandi
---

Renews a [Gandi](https://www.gandi.net/) v5 API personal access token via the
[Access Tokens](https://api.gandi.net/docs/organization/#v5-organization-access-tokens) endpoint.

The secret payload is the current Gandi access token. On rotation the handler:

1. Reads the current token from the pubsub message.
2. `POST`s to `https://api.gandi.net/v5/organization/access-tokens` with `Authorization: Bearer <current token>`.
3. Stores the `access_token` from the response as a new secret version.

The new token inherits the same name and scopes as the one that issued the request.

## Configuration

Set the handler label on the secret:

```txt
<handler_label_key>=gandi
```

No additional labels required.
