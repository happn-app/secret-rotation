---
title: Password
---

Generates a new random password to replace the rotating secret, using
[`sethvargo/go-password`](https://github.com/sethvargo/go-password).

The generated password is stored as a new secret version. Generation is controlled by the `password_constraints` label.

## Constraints

The `password_constraints` label is a `;`-separated list of `key=value` pairs. Missing keys fall back to defaults:

| Key         | Default | Description                          |
| ----------- | ------- | ------------------------------------ |
| `length`    | 32      | Total password length                |
| `uppercase` | 1       | Allow uppercase letters (`> 0` = on) |
| `lowercase` | 1       | Lowercase letters (implied)          |
| `digits`    | 1       | Number of digits                     |
| `special`   | 1       | Number of special characters         |

Repeated characters are allowed.

## Configuration

Set the handler label on the secret:

```txt
<handler_label_key>=password
password_constraints=length=32;uppercase=1;lowercase=1;digits=1;special=1
```

| Label                  | Required | Description                                                                                                   |
| ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `password_constraints` | no       | Password generation constraints. Defaults to `length=32;uppercase=1;lowercase=1;digits=1;special=1` if unset. |
