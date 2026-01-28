---
title: Config
---

## Example

Default path: `/etc/secret-rotation/config.yaml`, env var: `CONFIG_PATH`

```yaml
host: 0.0.0.0
gcp_project_id: happn-preprod
pubsub_subscription: my-subscription
handler_label_key: rotation
```

## Host

The IP to bind the API to, the API being used for health checks and readiness probes

## GCP Project ID

The GCP Project ID on which to create a pubsub client (the project which holds the subscription / topics / Secret Manager)

## PubSub Subscription

The PubSub subscription to subscribe to to get secret rotation messages from Google Secret Manager

## Handler Label Key

The label to check on the secret to determine the handler to use to renew the secret. For instance, if `handler_label_key`
is "rotation-handler", then a secret with a label `rotation-handler=gandi` will use the gandi handler to renew the secret.
