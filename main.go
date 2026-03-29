package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	setupWorkingDir()

	// Инициализация логирования в файл и консоль
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	// Log working directory for debugging
	cwd, _ := os.Getwd()
	log.Printf("Working directory: %s", cwd)

	loadConfig()

	// Initialize nonce cache and start cleaner
	nonceCache = make(map[string]time.Time)
	go nonceCleaner()

	// Initialize memory keys map for limited-access clients
	memoryKeys = make(map[string]string)

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	argPort := fs.String("port", "8443", "Port")
	argGetToken := fs.Bool("get-token", false, "Print API Token")
	argCreateUser := fs.String("create-user", "", "Password (Memory Key) for the new user")
	argUpdateUser := fs.String("update-user", "", "Key ID of the user to update")
	argDeleteUser := fs.String("delete-user", "", "Key ID of the user to delete")
	argUserName := fs.String("name", "Admin", "Name for the new user")
	argUserRole := fs.String("role", "admin", "Role (admin/user)")
	argUserQuota := fs.Int64("quota", 10, "User quota in GB (default 10)")
	fs.Parse(os.Args[1:])
	startTime = time.Now()

	if *argGetToken {
		log.Printf("ERROR: ApiToken system is disabled. Use Memory Keys.")
		return
	}

	// Removing ApiToken logic

	if *argPort != "" {
		conf.Port = *argPort
	}

	// Persist any changes back to config.json so it matches the running server
	saveConfig()

	// Print status at startup
	log.Printf("Startup: Running in User-Only mode (No Master Key)")

	// Инициализация БД
	dbPath := dbFile
	log.Printf("Opening database: %s", dbPath)
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("DB Open Error: %v", err)
	}

	// Test if database is accessible
	err = db.Ping()
	if err != nil {
		log.Fatalf("DB Connection Error: %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, size INTEGER, created DATETIME, has_thumb BOOLEAN DEFAULT 0, owner_key TEXT DEFAULT NULL)")
	if err != nil {
		log.Fatalf("Table Init Error: %v", err)
	}

	// Create users table for storing memory keys, names, and roles
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (key_id TEXT PRIMARY KEY, memory_key TEXT, name TEXT DEFAULT NULL, role TEXT DEFAULT 'user', quota_bytes INTEGER DEFAULT 10737418240, created_date DATETIME DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		log.Fatalf("Users Table Init Error: %v", err)
	}

	// Migration: Add columns if they don't exist
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN key_id TEXT")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN name TEXT DEFAULT NULL")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")

	quotaBytes := *argUserQuota * 1024 * 1024 * 1024

	// Редактирование существующего пользователя
	if *argUpdateUser != "" {
		id := *argUpdateUser
		err = updateUserInDB(id, *argUserName, *argUserRole, quotaBytes)
		if err != nil {
			log.Fatalf("❌ Ошибка при обновлении пользователя: %v", err)
		}

		fmt.Println(strings.Repeat("-", 40))
		fmt.Printf("✅ Пользователь [%s] обновлен!\n", id)
		fmt.Printf("Новое имя:  %s\n", *argUserName)
		fmt.Printf("Новая роль: %s\n", *argUserRole)
		fmt.Printf("Новая квота: %d GB\n", *argUserQuota)
		fmt.Println(strings.Repeat("-", 40))
		os.Exit(0)
	}

	// Удаление пользователя через CLI
	if *argDeleteUser != "" {
		id := *argDeleteUser
		var encKey string
		err = db.QueryRow("SELECT memory_key FROM users WHERE key_id = ?", id).Scan(&encKey)
		if err != nil {
			log.Fatalf("❌ Ошибка: Пользователь с ID [%s] не найден в базе.", id)
		}

		// Получаем реальный ключ, чтобы знать, какую папку удалять
		userKey := decryptKeyForUser(encKey, id)
		if userKey == "" {
			userKey = decryptKeyForUser(encKey, "legacy")
		}

		_, err = db.Exec("DELETE FROM users WHERE key_id = ?", id)
		if err != nil {
			log.Fatalf("❌ Ошибка при удалении из БД: %v", err)
		}

		if userKey != "" {
			db.Exec("DELETE FROM files WHERE owner_key = ?", userKey)
			os.RemoveAll(filepath.Join(storageDir, userKey))
		}
		fmt.Printf("✅ Пользователь [%s] и все его файлы успешно удалены.\n", id)
		os.Exit(0)
	}

	// Ручное создание пользователя через флаги (безопасно по SSH)
	if *argCreateUser != "" {
		key := *argCreateUser
		id := keyToID(key)

		// Используем либо переданную квоту, либо квоту из конфига
		quotaFlagWasSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "quota" {
				quotaFlagWasSet = true
			}
		})
		finalQuota := quotaBytes
		if !quotaFlagWasSet {
			finalQuota = conf.UserQuota
		}

		err = saveMemoryKeyToDB(key, *argUserName, *argUserRole, finalQuota)
		if err != nil {
			log.Fatalf("❌ Ошибка при создании пользователя: %v", err)
		}

		fmt.Println(strings.Repeat("-", 40))
		fmt.Printf("✅ Пользователь создан успешно!\n")
		fmt.Printf("Имя:  %s\n", *argUserName)
		fmt.Printf("Роль: %s\n", *argUserRole)
		fmt.Printf("Квота: %d GB\n", finalQuota/(1024*1024*1024))
		fmt.Printf("ID:   %s (это увидит сервер в заголовках)\n", id)
		fmt.Println("Пароль (Memory Key) сохранен в БД в зашифрованном виде.")
		fmt.Println(strings.Repeat("-", 40))

		// После создания пользователя завершаем работу или продолжаем?
		// Обычно для CLI команд лучше завершить.
		os.Exit(0)
	}

	log.Printf("✓ Database initialized successfully")

	// Load existing memory keys from database into memory
	loadMemoryKeysFromDB()

	// Роутинг
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/api", secureApiHandler) // Primary secure endpoint

	// Legacy endpoints (re-routing to secureApiHandler)
	mux.HandleFunc("/list", secureApiHandler)
	mux.HandleFunc("/download", secureApiHandler)
	mux.HandleFunc("/delete", secureApiHandler)
	mux.HandleFunc("/root", secureApiHandler)
	mux.HandleFunc("/stats", secureApiHandler)
	mux.HandleFunc("/mkdir", secureApiHandler)
	mux.HandleFunc("/exec", secureApiHandler)

	srv := &http.Server{
		Addr:         ":" + conf.Port,
		Handler:      mux,
		ReadTimeout:  60 * time.Minute,
		WriteTimeout: 60 * time.Minute,
	}

	separator := strings.Repeat("=", 60)
	log.Print(separator)
	log.Printf("🚀 Atlant Cloud v2.0 | Zero-Knowledge Architecture")
	log.Printf("✓ Memory Keys are now random and unique per user")
	log.Printf("✓ Server is a storage-only provider (no body decryption)")
	log.Print(separator)
	log.Printf("Server starting on port %s", conf.Port)
	log.Printf("🚀 Atlant Cloud v3.0 | Zero-Knowledge Architecture")
	log.Printf("Storage directory: %s", storageDir)
	log.Printf(separator)

	log.Fatal(srv.ListenAndServe())
}

func setupWorkingDir() {
	err := os.MkdirAll(workingDir, 0755)
	if err != nil {
		log.Printf("WARNING: Failed to create %s: %v", workingDir, err)
	}

	path := filepath.Join(workingDir, thumbDir)
	err = os.MkdirAll(path, 0755)
	if err != nil {
		log.Printf("WARNING: Failed to create storage directories: %v", err)
	}

	err = os.Chdir(workingDir)
	if err != nil {
		log.Printf("WARNING: Failed to change to working directory %s: %v", workingDir, err)
		log.Printf("Continuing with current directory...")
		return
	}

	log.Printf("✓ Changed to working directory: %s", workingDir)
}

func loadConfig() {
	d, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Config not found, generating new keys...")
		conf = Config{
			Port:      "8443",
			UserQuota: 10737418240,
		}
		saveConfig()
		log.Printf("Config saved to %s", configFile)
		return
	}

	err = json.Unmarshal(d, &conf)
	if err != nil {
		log.Fatalf("ERROR: Failed to parse config.json: %v", err)
	}

	if conf.UserQuota == 0 {
		conf.UserQuota = 10737418240
		saveConfig()
	}

	log.Printf("✓ Config loaded, Port=%s", conf.Port)
	log.Printf("✓ User quota limit: %.2f GB", float64(conf.UserQuota)/1e9)
}

func saveConfig() {
	d, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		log.Printf("ERROR: Failed to marshal config: %v", err)
		return
	}

	err = os.WriteFile(configFile, d, 0600)
	if err != nil {
		log.Printf("ERROR: Failed to write config to %s: %v", configFile, err)
		return
	}

	log.Printf("✓ Config saved to %s", configFile)
}
