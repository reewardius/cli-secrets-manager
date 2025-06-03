package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/term"
)

const secretsFile = "secrets.json"

var (
	secrets     = make(map[string]string)
	secretsLock sync.Mutex
)

func loadSecrets() {
	file, err := os.Open(secretsFile)
	if err != nil {
		return
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&secrets)
}

func saveSecrets() {
	file, err := os.Create(secretsFile)
	if err != nil {
		fmt.Println("Failed to save secrets:", err)
		return
	}
	defer file.Close()
	json.NewEncoder(file).Encode(secrets)
}

func addSecret(key, value string) {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	secrets[key] = value
	saveSecrets()
}

func getSecret(key string) {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	if val, ok := secrets[key]; ok {
		fmt.Println(val)
	} else {
		os.Exit(1)
	}
}

func listSecrets() {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	if len(secrets) == 0 {
		fmt.Println("No secrets stored.")
		return
	}
	for k, v := range secrets {
		fmt.Printf("%s = %s\n", k, v)
	}
}

func deleteSecret(key string) {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	if _, ok := secrets[key]; ok {
		delete(secrets, key)
		saveSecrets()
		fmt.Println("Deleted.")
	} else {
		fmt.Println("Not found.")
	}
}

func importCert(filename string) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pem", ".crt":
		importPEMCertificate(filename)
	case ".der":
		importDERCertificate(filename)
	case ".p12", ".pfx":
		importP12Certificate(filename)
	default:
		fmt.Println("Unsupported certificate format:", ext)
	}
}

func importPEMCertificate(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	var certs []string
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			data = rest
			continue
		}

		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("Invalid certificate:", err)
			return
		}

		certs = append(certs, string(pem.EncodeToMemory(block)))
		data = rest
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in file.")
		return
	}

	keyName := "cert_" + strings.TrimSuffix(filepath.Base(filename), ext)
	secretsLock.Lock()
	secrets[keyName] = strings.Join(certs, "\n")
	secretsLock.Unlock()
	saveSecrets()
	fmt.Printf("Imported: %s\n", keyName)
}

func importDERCertificate(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		fmt.Println("Invalid DER certificate:", err)
		return
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(block)

	keyName := "cert_" + strings.TrimSuffix(filepath.Base(filename), ".der")
	secretsLock.Lock()
	secrets[keyName] = string(pemData)
	secretsLock.Unlock()
	saveSecrets()
	fmt.Printf("Imported: %s\n", keyName)
}

func importP12Certificate(filename string) {
	fmt.Print("Enter password for .p12/.pfx: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	// Decode PKCS#12 (PFX) bundle
	blocks, err := pkcs12ToPEM(data, string(passBytes))
	if err != nil {
		fmt.Println("Failed to parse P12:", err)
		return
	}

	var pemCerts []string
	for _, b := range blocks {
		pemCerts = append(pemCerts, string(pem.EncodeToMemory(b)))
	}

	keyName := "cert_" + strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	secretsLock.Lock()
	secrets[keyName] = strings.Join(pemCerts, "\n")
	secretsLock.Unlock()
	saveSecrets()
	fmt.Printf("Imported: %s\n", keyName)
}

func pkcs12ToPEM(p12 []byte, password string) ([]*pem.Block, error) {
	// Uses deprecated x/crypto/pkcs12
	priv, cert, caCerts, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		return nil, err
	}

	var blocks []*pem.Block

	if priv != nil {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err == nil {
			blocks = append(blocks, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		}
	}

	if cert != nil {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	for _, ca := range caCerts {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	}

	return blocks, nil
}

func printHelp() {
	fmt.Println(`Secrets Manager CLI
Usage:
  add <key> <value>         — Store a new secret
  get <key>                 — Get a secret (prints value only)
  list                      — Show all stored secrets
  delete <key>              — Delete a secret
  import-cert <path>        — Import a TLS cert (.pem, .crt, .der, .p12)
`)
}

func main() {
	loadSecrets()

	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "add":
		if len(os.Args) != 4 {
			fmt.Println("Usage: add <key> <value>")
			return
		}
		addSecret(os.Args[2], os.Args[3])

	case "get":
		if len(os.Args) != 3 {
			fmt.Println("Usage: get <key>")
			return
		}
		getSecret(os.Args[2])

	case "list":
		listSecrets()

	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Usage: delete <key>")
			return
		}
		deleteSecret(os.Args[2])

	case "import-cert":
		if len(os.Args) != 3 {
			fmt.Println("Usage: import-cert <file>")
			return
		}
		importCert(os.Args[2])

	default:
		printHelp()
	}
}
