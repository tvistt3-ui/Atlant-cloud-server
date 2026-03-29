package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// keyToID calculates 16-char ID from memory key
func keyToID(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])[:16]
}

// deobfuscateID reverts the time-based obfuscation to find the real ID.
func deobfuscateID(id string) string {
	// Возвращаем ID как есть, чтобы соответствовать упрощенной логике клиента
	// и избежать проблем с поиском ключа в базе.
	return id
}

// fixKey ensures the master key is exactly 32 bytes by padding with null bytes
// This allows flexible key input (any length) while maintaining AES-256 compatibility
func fixKey(key string) []byte {
	fixed := make([]byte, 32)
	copy(fixed, []byte(key))
	return fixed
}

func getCryptoStream(k, iv []byte) (cipher.Stream, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(b, iv), nil
}

// securePath verifies that requestedPath is within baseDir and returns the absolute path.
// This prevents path traversal attacks like ../../etc/passwd
func securePath(requested string, baseDir string) (string, error) {
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %v", err)
	}

	// Очищаем requested от ведущих слэшей и нормализуем, чтобы он был относительным к baseDir
	cleanRequested := filepath.Clean(strings.TrimLeft(requested, "/\\"))
	if cleanRequested == "." {
		cleanRequested = "" // If after cleaning it's just ".", means root of baseDir
	}

	finalPath := filepath.Join(baseAbs, cleanRequested)
	finalAbs, err := filepath.Abs(finalPath)
	if err != nil {
		return "", fmt.Errorf("invalid path after join: %v", err)
	}

	// Убедимся, что полученный путь находится внутри baseAbs
	if !strings.HasPrefix(finalAbs, baseAbs) {
		return "", fmt.Errorf("path traversal detected: %s escapes %s", requested, baseDir)
	}
	return finalAbs, nil
}

// runShellCommand executes a shell command in a cross-platform way.
// On Android it prefers /system/bin/sh, on Windows it uses cmd.exe /C,
// otherwise it tries the POSIX sh from PATH.
func runShellCommand(command string) ([]byte, error) {
	command = strings.TrimSpace(command)
	// Default timeout for commands
	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", command).CombinedOutput()
	}

	// On Android, use explicit shell path to avoid PATH issues
	if runtime.GOOS == "android" {
		return exec.CommandContext(ctx, "/system/bin/sh", "-c", command).CombinedOutput()
	}

	// Fallback to bash from PATH on other Unix-like systems
	return exec.CommandContext(ctx, "bash", "-c", command).CombinedOutput()
}

func isImg(n string) bool {
	ext := strings.ToLower(filepath.Ext(n))
	return ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".webp"
}

func generateRandomString(n int) string {
	// Генерируем n случайных печатаемых символов для ключа
	// Используем буквы, цифры и некоторые спецсимволы
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	b := make([]byte, n)
	for i := range b {
		num := make([]byte, 1)
		rand.Read(num)
		b[i] = charset[int(num[0])%len(charset)]
	}
	return string(b)
}

func maskIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])[:8]
}

// checkAndAddNonce returns true if nonce was not seen and registers it with expiry.
func checkAndAddNonce(n string) bool {
	nonceMutex.Lock()
	defer nonceMutex.Unlock()
	now := time.Now()
	// purge expired entries lazily
	for k, exp := range nonceCache {
		if exp.Before(now) {
			delete(nonceCache, k)
		}
	}
	if exp, ok := nonceCache[n]; ok {
		if exp.After(now) {
			return false
		}
	}
	nonceCache[n] = now.Add(nonceTTL)
	return true
}

// nonceCleaner periodically removes expired nonces
func nonceCleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		nonceMutex.Lock()
		now := time.Now()
		for k, exp := range nonceCache {
			if exp.Before(now) {
				delete(nonceCache, k)
			}
		}
		nonceMutex.Unlock()
	}
}

func isSensitiveCommand(cmd string) bool {
	switch cmd {
	case "exec", "stats", "generate_key", "list_users", "delete_user", "root_list", "root_get", "root_delete", "root_mkdir":
		return true
	}
	return false
}
