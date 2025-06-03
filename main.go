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
		fmt.Println("Ошибка при сохранении:", err)
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
	fmt.Println("Секрет добавлен.")
}

func getSecret(key string) {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	if val, ok := secrets[key]; ok {
		fmt.Printf("%s = %s\n", key, val)
	} else {
		fmt.Println("Секрет не найден.")
	}
}

func listSecrets() {
	secretsLock.Lock()
	defer secretsLock.Unlock()
	if len(secrets) == 0 {
		fmt.Println("Нет сохранённых секретов.")
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
		fmt.Println("Секрет удалён.")
	} else {
		fmt.Println("Секрет не найден.")
	}
}

func importCert(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Ошибка чтения файла:", err)
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
			fmt.Println("Невалидный сертификат:", err)
			return
		}

		certs = append(certs, string(pem.EncodeToMemory(block)))
		data = rest
	}

	if len(certs) == 0 {
		fmt.Println("Сертификаты не найдены в файле.")
		return
	}

	secretsLock.Lock()
	defer secretsLock.Unlock()

	keyName := "cert_" + strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	secrets[keyName] = strings.Join(certs, "\n")
	saveSecrets()
	fmt.Printf("Импортировано как ключ: %s\n", keyName)
}

func printUsage() {
	fmt.Println(`Secrets Manager CLI
Использование:
  add <key> <value>         — Добавить секрет
  get <key>                 — Получить значение
  list                      — Показать все
  delete <key>              — Удалить
  import-cert <file.pem>    — Импортировать TLS-сертификат
`)
}

func main() {
	loadSecrets()

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "add":
		if len(os.Args) != 4 {
			fmt.Println("Использование: add <key> <value>")
			return
		}
		addSecret(os.Args[2], os.Args[3])

	case "get":
		if len(os.Args) != 3 {
			fmt.Println("Использование: get <key>")
			return
		}
		getSecret(os.Args[2])

	case "list":
		listSecrets()

	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Использование: delete <key>")
			return
		}
		deleteSecret(os.Args[2])

	case "import-cert":
		if len(os.Args) != 3 {
			fmt.Println("Использование: import-cert <file.pem>")
			return
		}
		importCert(os.Args[2])

	default:
		printUsage()
	}
}
