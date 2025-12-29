# NodeGraph Generator

A go webserver to generate a service graph for Grafana

## NOTES

- Arc = ratio failed vs success
- mainstat: RPS
- secondarystat: Latency (p95)
- detail__avg_latency: Latency (avg)
- detail__p50_latency: Latency (p50)

## TODO

customize max depth + source/starting service

## Development

### Release

Push a tag with format `vx.y.z`, and let the CI build and publish

### Testing

Manual testing can be done using `docker compose`, which will:

- Build the `nodegraph-generator` image
- Run a grafana server with anonymous / admin auth
- Provision grafana with the infinity datasource connected to `nodegraph-generator`'s API
- Provision grafana with a service graph dashboard, and make it the home dashboard

For it to work, you need to port forward `vmauth` from the `monitoring` cluster

```sh
kubectl --context monitoring port-forward --namespace victoriametrics services/vmauth-vmauth-lb 8427
```
