# cli-secrets-manager

A simple command-line tool for managing secrets and importing TLS certificates written in Go.

#### Features

- Store and retrieve secrets securely
- Import TLS certificates in various formats (.pem, .crt, .der, .p12/.pfx)
- List all stored secrets
- Delete secrets
- Thread-safe operations with mutex locks

#### Prerequisites

- Go 1.16 or higher
- Git (for cloning dependencies)

#### 🔧 Build

Building from Source

Clone or download the source code
```bash
git clone <your-repository-url>
cd secrets-manager
```
Initialize Go module
```bash
go mod init secrets-manager
```

3. Install dependencies
```bash
go get golang.org/x/crypto/pkcs12
go get golang.org/x/term
```

5. Build the application
```bash
go build -o secrets-manager
```

### Usage
#### Basic Commands
**Help**
```bash
./secrets-manager help
```

**Add a secret**
```bash
./secrets-manager add <key> <value>
```
**Example:**
```bash
./secrets-manager add api_key "your-secret-api-key"
./secrets-manager add db_password "super-secure-password"
```
**Get a secret**
```bash
./secrets-manager get <key>
```
##### **Example:**
```bash
./secrets-manager get api_key
```
**List all secrets**
```bash
./secrets-manager list
```
**Delete a secret**
```bash.
/secrets-manager delete <key>
```
##### **Example:**
```bash
./secrets-manager delete api_key
```
---
### Certificate Import
#### Import TLS certificates
```bash
./secrets-manager import-cert <certificate-file>
```
#### Supported formats:

- `.pem` - PEM encoded certificates
- `.crt` - Certificate files
- `.der` - DER encoded certificates
- `.p12` / `.pfx` - PKCS#12 certificate bundles (password protected)

#### Example:
```bash
./secrets-manager import-cert server.crt
./secrets-manager import-cert certificate.pem
./secrets-manager import-cert bundle.p12
```
For `.p12` and `.pfx` files, you will be prompted to enter the password.

**Retrieve imported certificates**
```bash
./secrets-manager get cert_<filename>
```
#### Example:
```bash
./secrets-manager get cert_server
```

---
#### 📁 Example of secrets.json
```json
{
  "db_pass": "s3cr3t",
  "cert_mycert": "-----BEGIN CERTIFICATE-----\nMIID...snip...\n-----END CERTIFICATE-----"
}
```
#### Data Storage

1. Secrets are stored in a local secrets.json file in the same directory as the executable
2. The file is created automatically when you add your first secret
3. All operations are thread-safe using mutex locks
