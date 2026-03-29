package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"
)

// --- DATABASE AND QUOTA HELPERS ---

func loadMemoryKeysFromDB() {
	// Используем IFNULL, чтобы сканирование не падало на пустых значениях
	rows, err := db.Query("SELECT IFNULL(key_id, ''), memory_key FROM users")
	if err != nil {
		log.Printf("ERROR: Failed to load memory keys from DB: %v", err)
		return
	}
	defer rows.Close()

	memoryKeysMux.Lock()
	defer memoryKeysMux.Unlock()

	count := 0
	for rows.Next() {
		var keyID, encKey, decryptedKey string
		if err := rows.Scan(&keyID, &encKey); err != nil {
			continue
		}

		// 1. Пробуем расшифровать с солью из keyID
		if keyID != "" {
			decryptedKey = decryptKeyForUser(encKey, keyID)
		}

		// 2. Если не вышло, пробуем старую "legacy" соль
		if decryptedKey == "" {
			decryptedKey = decryptKeyForUser(encKey, "legacy")
		}

		if decryptedKey != "" {
			actualID := keyToID(decryptedKey)
			memoryKeys[actualID] = decryptedKey
			log.Printf("DEBUG: Registered KeyID [%s] from DB", actualID)
			count++
		}
	}
	log.Printf("INFO: Loaded %d privacy-protected keys from database", count)
}

func saveMemoryKeyToDB(key, name, role string, quota int64) error {
	id := keyToID(key)
	enc := encryptKeyForUser(key, id)
	_, err := db.Exec("INSERT INTO users (key_id, memory_key, name, role, quota_bytes) VALUES (?, ?, ?, ?, ?)", id, enc, name, role, quota)
	return err
}

func updateUserInDB(id, name, role string, quota int64) error {
	_, err := db.Exec("UPDATE users SET name = ?, role = ?, quota_bytes = ? WHERE key_id = ?", name, role, quota, id)
	return err
}

func getUserQuota(ownerKey string) (int64, error) {
	id := keyToID(ownerKey)
	var quota int64
	// Search by key_id because memory_key column is encrypted
	err := db.QueryRow("SELECT quota_bytes FROM users WHERE key_id = ?", id).Scan(&quota)
	if err != nil {
		return 0, err
	}
	return quota, nil
}

func isUserAdmin(id string) bool {
	var role string
	err := db.QueryRow("SELECT role FROM users WHERE key_id = ?", id).Scan(&role)
	if err != nil {
		return false
	}
	return role == "admin"
}

func canUserUpload(ownerKey string, fileSize int64) (bool, int64, int64, error) {
	quota, err := getUserQuota(ownerKey)
	if err != nil {
		return false, 0, 0, err
	}

	var usedBytes sql.NullInt64
	err = db.QueryRow("SELECT SUM(size) FROM files WHERE owner_key = ?", ownerKey).Scan(&usedBytes)
	if err != nil && err != sql.ErrNoRows {
		return false, 0, 0, err
	}

	used := usedBytes.Int64
	remaining := quota - used
	canUpload := remaining >= fileSize

	return canUpload, used, remaining, nil
}

func encryptKeyForUser(k string, id string) string {
	iv := make([]byte, 16)
	rand.Read(iv)

	// PER-USER DERIVED KEY for encryption of the user's master key!
	// This ensures that even if one key is compromised, the encryption scheme is unique.
	salt := sha256.Sum256([]byte(id + "atlant-default-salt-2026"))
	block, _ := aes.NewCipher(salt[:])

	stream := cipher.NewCTR(block, iv)
	data := []byte(k)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)
	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(encrypted)
}

func decryptKeyForUser(enc string, id string) string {
	parts := strings.Split(enc, ":")
	if len(parts) != 2 {
		return ""
	}
	iv, _ := hex.DecodeString(parts[0])
	data, _ := hex.DecodeString(parts[1])

	salt := sha256.Sum256([]byte(id + "atlant-default-salt-2026"))
	block, _ := aes.NewCipher(salt[:])

	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return string(decrypted)
}

func encryptKey(k string) string {
	// Fallback to legacy master key root
	return encryptKeyForUser(k, "legacy")
}

func decryptKey(enc string) string {
	// Fallback to legacy master key root
	return decryptKeyForUser(enc, "legacy")
}
