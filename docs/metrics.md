---
title: Metrics
---

- `secret_rotation_count`
  - labels: handler, secret_id
  - type: COUNTER

- `secret_rotation_duration_seconds`
  - labels: handler, secret_id
  - type: HISTOGRAM

- `secret_rotation_error_count`
  - labels: error, handler, secret_id
  - type: COUNTER
