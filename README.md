# python.mosquitto-bws2passwd
Init container to generate a passwd.txt file from Bitwarden Secrets

## Usage

```
bws2passwd -f PATTERN [-o FILE] [-i FILE]
```

| Flag | Description |
|---|---|
| `-f`, `--filter` | Regular expression to filter secrets by key/name (required). |
| `-o`, `--output` | Write output to FILE instead of stdout. |
| `-i`, `--input` | Existing password file. When a secret's password matches the stored digest, the existing hash is reused instead of generating a new one. |
| `-v`, `--verbose` | Report entry status (added/changed/unchanged/dropped) on stderr. |

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `BWS_ACCESS_TOKEN` | Yes | Bitwarden SM machine account access token. |
| `BWS_ORGANIZATION_ID` | Yes | Bitwarden organization ID. |
