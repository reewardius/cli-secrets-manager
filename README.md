# cli-secrets-manager

#### 🔧 Build

```bash
go mod init secrets
go get golang.org/x/term
go get software.sslmate.com/src/go-pkcs12
go build -o secrets
```
#### 🧪 Usage
| Command                      | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `./secrets add key value`    | Save a new secret                             |
| `./secrets get key`          | Print value only (no key)                     |
| `./secrets list`             | Show all secrets                              |
| `./secrets delete key`       | Remove a secret                               |
| `./secrets import-cert file` | Import TLS cert (.pem, .crt, .der, .p12/.pfx) |

📁 Example of secrets.json
```json
{
  "db_pass": "s3cr3t",
  "cert_mycert": "-----BEGIN CERTIFICATE-----\nMIID...snip...\n-----END CERTIFICATE-----"
}
```
