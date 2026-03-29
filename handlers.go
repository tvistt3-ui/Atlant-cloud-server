package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/disintegration/imaging"
)

// --- HTTP HANDLERS ---

func handleList(w http.ResponseWriter, userKey string, subDir string) {
	query := "SELECT id, name, size, created, has_thumb, owner_key FROM files"
	var args []interface{}
	if userKey != "" {
		query += " WHERE owner_key = ?"
		args = append(args, userKey)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("ERROR: DB Query Failed: %v", err)
		return
	}
	defer rows.Close()

	logicalRootForUser := filepath.Join(storageDir, userKey)
	targetAbsDir, err := securePath(subDir, logicalRootForUser)
	if err != nil {
		return
	}
	targetAbsDir, _ = filepath.Abs(targetAbsDir)

	var list []FileRecord
	addedFolders := make(map[string]bool)

	for rows.Next() {
		var f FileRecord
		var ht bool
		var rawDBPath string
		rows.Scan(&f.ID, &rawDBPath, &f.Size, &f.Created, &ht, &f.OwnerKey)

		fileDiskAbsPath, _ := filepath.Abs(rawDBPath)
		if strings.HasPrefix(fileDiskAbsPath, targetAbsDir) {
			relPathToTarget, err := filepath.Rel(targetAbsDir, fileDiskAbsPath)
			if err != nil {
				continue
			}

			if !strings.Contains(relPathToTarget, string(filepath.Separator)) {
				fileInfo, _ := os.Stat(fileDiskAbsPath)
				if fileInfo != nil && fileInfo.IsDir() {
					if !addedFolders[relPathToTarget] {
						list = append(list, FileRecord{
							ID:       0,
							Filename: filepath.ToSlash(filepath.Join(subDir, relPathToTarget)),
							Is_dir:   true,
							Name:     relPathToTarget,
							OwnerKey: keyToID(userKey),
						})
						addedFolders[relPathToTarget] = true
					}
				} else {
					f.Filename = filepath.ToSlash(filepath.Join(subDir, relPathToTarget))
					if ht {
						// Возвращаем логический путь. Клиент должен запросить превью через команду "thumb"
						f.Thumbnail = f.Filename
					}
					f.Is_dir = false
					f.Name = filepath.Base(rawDBPath)
					list = append(list, f)
				}
			} else {
				firstSubDir := strings.SplitN(relPathToTarget, string(filepath.Separator), 2)[0]
				if !addedFolders[firstSubDir] {
					list = append(list, FileRecord{
						ID:       0,
						Filename: filepath.ToSlash(filepath.Join(subDir, firstSubDir)),
						Is_dir:   true,
						Name:     firstSubDir,
						OwnerKey: keyToID(userKey),
					})
					addedFolders[firstSubDir] = true
				}
			}
		}
	}
	d, _ := json.Marshal(list)
	encryptAndSend(w, d, fixKey(userKey))
}

func handleExec(w http.ResponseWriter, cmd string, key []byte) {
	out, err := runShellCommand(cmd)
	if err != nil {
		out = []byte(fmt.Sprintf("Error: %v\nOutput: %s", err, out))
	}
	encryptAndSend(w, out, key)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: Upload request from %s", maskIP(r.RemoteAddr))

	// 1. Identification via obfuscated Key ID in header
	obfuscatedKeyID := r.Header.Get("X-Auth-Key-ID")
	if obfuscatedKeyID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	keyID := deobfuscateID(obfuscatedKeyID)
	if keyID == "" {
		log.Printf("ERROR: Upload - Invalid/Expired Key ID: %s", obfuscatedKeyID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	memoryKeysMux.Lock()
	userKey, ok := memoryKeys[keyID]
	memoryKeysMux.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	trafficKey := fixKey(userKey)

	// 2. Read and Decrypt Metadata
	metaHex := r.FormValue("meta")
	metaIvHex := r.Header.Get("X-Upload-Meta-IV")
	if metaHex == "" || metaIvHex == "" {
		encryptAndSend(w, []byte("Missing encrypted metadata"), trafficKey)
		return
	}
	metaIv, err := hex.DecodeString(metaIvHex)
	if err != nil || len(metaIv) != 16 {
		encryptAndSend(w, []byte("Invalid meta IV"), trafficKey)
		return
	}
	metaCipher, err := hex.DecodeString(metaHex)
	if err != nil {
		encryptAndSend(w, []byte("Invalid meta hex"), trafficKey)
		return
	}
	mb := make([]byte, len(metaCipher))
	mbStream, err := getCryptoStream(trafficKey, metaIv)
	if err != nil {
		encryptAndSend(w, []byte("Crypto error"), trafficKey)
		return
	}
	mbStream.XORKeyStream(mb, metaCipher)

	var metaReq EncryptedRequest
	if err := json.Unmarshal(mb, &metaReq); err != nil {
		encryptAndSend(w, []byte("Invalid meta JSON"), trafficKey)
		return
	}

	// 3. Form File
	f, h, err := r.FormFile("file")
	if err != nil {
		encryptAndSend(w, []byte("File error"), trafficKey)
		return
	}
	defer f.Close()

	if h.Size > 5*1024*1024*1024 {
		encryptAndSend(w, []byte("File too large (max 5GB)"), trafficKey)
		return
	}

	// 4. Quota Check
	if can, _, _, _ := canUserUpload(userKey, h.Size); !can {
		encryptAndSend(w, []byte("Storage quota exceeded"), trafficKey)
		return
	}

	// 5. Target Path
	base := filepath.Join(storageDir, userKey)
	targetDiskAbsPath, err := securePath(metaReq.Param, base)
	if err != nil {
		encryptAndSend(w, []byte("Invalid target path"), trafficKey)
		return
	}

	os.MkdirAll(targetDiskAbsPath, 0755)
	finalFilePathOnDisk := filepath.Join(targetDiskAbsPath, filepath.Base(h.Filename))

	// 6. Decrypt and Save File Content
	// Files are sent encrypted by client. We decrypt them here to store plain on server.
	fileIvHex := r.Header.Get("X-File-IV")
	if fileIvHex == "" {
		fileIvHex = r.Header.Get("X-Encryption-IV")
	}
	fileIv, err := hex.DecodeString(fileIvHex)
	if err != nil || len(fileIv) != 16 {
		encryptAndSend(w, []byte("Invalid file IV"), trafficKey)
		return
	}

	out, err := os.Create(finalFilePathOnDisk)
	if err != nil {
		encryptAndSend(w, []byte("Permission denied"), trafficKey)
		return
	}

	// Create decryption stream
	fBlock, err := aes.NewCipher(trafficKey)
	if err != nil {
		log.Printf("ERROR: AES initialization failed: %v", err)
		encryptAndSend(w, []byte("Cipher initialization error"), trafficKey)
		return
	}
	fStream := cipher.NewCTR(fBlock, fileIv)
	fReader := &cipher.StreamReader{S: fStream, R: f}

	io.Copy(out, fReader)
	out.Close()

	cwd, _ := os.Getwd()
	dbPath, _ := filepath.Rel(cwd, finalFilePathOnDisk)
	dbPath = filepath.ToSlash(dbPath)

	db.Exec("DELETE FROM files WHERE name = ?", dbPath)
	res, err := db.Exec("INSERT INTO files (name, size, created, has_thumb, owner_key) VALUES (?, ?, ?, ?, ?)",
		dbPath, h.Size, time.Now().Format("2006-01-02 15:04:05"), 0, userKey)

	if err == nil {
		id, _ := res.LastInsertId()
		if isImg(h.Filename) {
			log.Printf("DEBUG: Triggering thumbnail generation for %s (ID: %d)", h.Filename, id)
			go generateThumbnail(finalFilePathOnDisk, id)
		}
	}

	encryptAndSend(w, []byte("Successfully saved"), trafficKey)
}

func secureApiHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get obfuscated Key ID from header
	obfuscatedKeyID := r.Header.Get("X-Auth-Key-ID")
	if obfuscatedKeyID == "" {
		log.Printf("AUTH_ERROR: Missing X-Auth-Key-ID header from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// 2. De-obfuscate real Key ID
	keyID := deobfuscateID(obfuscatedKeyID)
	log.Printf("DEBUG: Incoming request. ObfuscatedID: %s -> RealID: %s", obfuscatedKeyID, keyID)

	if keyID == "" {
		log.Printf("AUTH_ERROR: deobfuscateID failed for %s", obfuscatedKeyID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// 3. Look up Memory Key
	memoryKeysMux.Lock()
	userKey, ok := memoryKeys[keyID]
	memoryKeysMux.Unlock()
	if !ok {
		log.Printf("AUTH_ERROR: KeyID [%s] not found in active memoryKeys map", keyID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	effectiveKey := fixKey(userKey)

	// 4. Decrypt Body
	ivHex := r.Header.Get("X-Encryption-IV")
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != 16 {
		log.Printf("CRYPTO_ERROR: Invalid IV [%s] from %s", ivHex, r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(effectiveKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	stream := cipher.NewCTR(block, iv)
	decryptedBody := make([]byte, len(body))
	stream.XORKeyStream(decryptedBody, body)

	var req EncryptedRequest
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		encryptAndSend(w, []byte("Invalid request JSON"), effectiveKey)
		return
	}

	// 5. Nonce check
	if req.Nonce == "" || !checkAndAddNonce(req.Nonce) {
		encryptAndSend(w, []byte("Invalid Nonce"), effectiveKey)
		return
	}

	// 6. Admin check for sensitive commands
	isAdmin := isUserAdmin(keyID)
	if isSensitiveCommand(req.Command) && !isAdmin {
		encryptAndSend(w, []byte("Access denied: Admin only"), effectiveKey)
		return
	}

	log.Printf("INFO: User %s (admin: %v) executing %s", keyID[:8], isAdmin, req.Command)

	switch req.Command {
	case "list":
		handleList(w, userKey, req.Param)
	case "download":
		handleDownloadByPath(w, req.Param, userKey, effectiveKey)
	case "delete":
		handleDelete(w, req.Param, userKey, effectiveKey)
	case "thumb":
		handleThumb(w, req.Param, userKey, effectiveKey)
	case "mkdir":
		handleMkdir(w, req.Param, userKey, effectiveKey)
	case "stats":
		handleStats(w, effectiveKey)
	case "exec":
		handleExec(w, req.Param, effectiveKey)
	case "generate_key":
		randomKey := generateRandomString(32)
		nickName, role := req.Param, "user"
		if strings.HasPrefix(nickName, "admin:") {
			role, nickName = "admin", strings.TrimPrefix(nickName, "admin:")
		}
		if nickName == "" {
			nickName = "Client_" + keyToID(randomKey)[:8]
		}

		memoryKeysMux.Lock()
		memoryKeys[keyToID(randomKey)] = randomKey
		memoryKeysMux.Unlock()
		saveMemoryKeyToDB(randomKey, nickName, role, userQuotaBytes)
		os.MkdirAll(filepath.Join(storageDir, randomKey), 0755)

		resp := map[string]string{
			"memory_key": randomKey,
			"name":       nickName,
			"role":       role,
			"key_id":     keyToID(randomKey),
		}
		data, _ := json.Marshal(resp)
		encryptAndSend(w, data, effectiveKey)
	case "list_users":
		memoryKeysMux.Lock()
		keys := make([]string, 0, len(memoryKeys))
		for k := range memoryKeys {
			keys = append(keys, k)
		}
		memoryKeysMux.Unlock()
		data, _ := json.Marshal(keys)
		encryptAndSend(w, data, effectiveKey)
	case "delete_user":
		targetID := req.Param // Ожидаем KeyID пользователя
		var userKey string
		err := db.QueryRow("SELECT memory_key FROM users WHERE key_id = ?", targetID).Scan(&userKey)
		if err != nil {
			encryptAndSend(w, []byte("User not found"), effectiveKey)
			return
		}

		// Расшифровываем, чтобы очистить файлы
		realKey := decryptKeyForUser(userKey, targetID)

		memoryKeysMux.Lock()
		delete(memoryKeys, targetID)
		memoryKeysMux.Unlock()

		db.Exec("DELETE FROM users WHERE key_id = ?", targetID)
		if realKey != "" {
			db.Exec("DELETE FROM files WHERE owner_key = ?", realKey)
			os.RemoveAll(filepath.Join(storageDir, realKey))
		}
		encryptAndSend(w, []byte("User deleted"), effectiveKey)
	case "root_list":
		handleRootList(w, req.Param, effectiveKey)
	case "root_get":
		handleRootGet(w, req.Param, effectiveKey)
	case "root_delete":
		handleRootDelete(w, req.Param, effectiveKey)
	case "root_mkdir":
		handleRootMkdir(w, req.Param, effectiveKey)
	default:
		encryptAndSend(w, []byte("Unknown command"), effectiveKey)
	}
}

func handleDownloadByPath(w http.ResponseWriter, path string, userKey string, key []byte) {
	baseDir := filepath.Join(storageDir, userKey)
	fp, err := securePath(path, baseDir)
	if err != nil {
		encryptAndSend(w, []byte("Access denied"), key)
		return
	}

	if _, err := os.Stat(fp); err != nil {
		encryptAndSend(w, []byte("File not found"), key)
		return
	}

	if err := streamEncryptedFile(w, fp, true, filepath.Base(fp), key); err != nil {
		encryptAndSend(w, []byte("Stream error"), key)
	}
}

func streamEncryptedFile(w http.ResponseWriter, filePath string, setDisposition bool, filename string, key []byte) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	if setDisposition {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	}

	iv := make([]byte, 16)
	rand.Read(iv)
	w.Header().Set("X-Encryption-IV", hex.EncodeToString(iv))

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)

	writer := &cipher.StreamWriter{S: stream, W: w}
	io.Copy(writer, f)
	return nil
}

func handleThumb(w http.ResponseWriter, path string, userKey string, key []byte) {
	// 1. Find file record in DB to get ID (thumbs are stored by ID for uniqueness)
	base := filepath.Join(storageDir, userKey)
	fp, err := securePath(path, base)
	if err != nil {
		encryptAndSend(w, []byte("Access denied"), key)
		return
	}

	cwd, _ := os.Getwd()
	rel, _ := filepath.Rel(cwd, fp)
	dbName := filepath.ToSlash(rel)

	var fid int
	err = db.QueryRow("SELECT id FROM files WHERE name = ? AND owner_key = ?", dbName, userKey).Scan(&fid)
	if err != nil {
		encryptAndSend(w, []byte("Thumb not found"), key)
		return
	}

	thumbPath := filepath.Join(thumbDir, fmt.Sprintf("thumb_%d.jpg", fid))
	if err := streamEncryptedFile(w, thumbPath, false, "", key); err != nil {
		encryptAndSend(w, []byte("Thumb not found"), key)
	}
}

func handleDelete(w http.ResponseWriter, path string, userKey string, key []byte) {
	base := filepath.Join(storageDir, userKey)
	fp, err := securePath(path, base)
	if err != nil {
		encryptAndSend(w, []byte("Access denied"), key)
		return
	}

	cwd, _ := os.Getwd()
	relPath, _ := filepath.Rel(cwd, fp)
	internalName := filepath.ToSlash(relPath)

	db.Exec("DELETE FROM files WHERE name = ? OR name LIKE ?", internalName, internalName+"/%")
	os.RemoveAll(fp)
	encryptAndSend(w, []byte("Deleted"), key)
}

func handleMkdir(w http.ResponseWriter, dir string, userKey string, key []byte) {
	base := filepath.Join(storageDir, userKey)
	target, err := securePath(dir, base)
	if err != nil {
		encryptAndSend(w, []byte("Access denied"), key)
		return
	}

	os.MkdirAll(target, 0755)
	encryptAndSend(w, []byte("Directory created"), key)
}

func handleRootList(w http.ResponseWriter, path string, key []byte) {
	if path == "" {
		path = "/"
	}
	if !filepath.IsAbs(path) {
		path = "/" + path
	}
	path = filepath.Clean(path)

	entries, err := os.ReadDir(path)
	if err != nil {
		encryptAndSend(w, []byte(err.Error()), key)
		return
	}
	res := []RootFileInfo{}
	for _, e := range entries {
		info, _ := e.Info()
		var s int64
		if info != nil {
			s = info.Size()
		}
		res = append(res, RootFileInfo{Name: e.Name(), IsDir: e.IsDir(), Size: s, Path: filepath.Join(path, e.Name())})
	}
	data, _ := json.Marshal(res)
	encryptAndSend(w, data, key)
}

func handleRootGet(w http.ResponseWriter, path string, key []byte) {
	if !filepath.IsAbs(path) {
		path = "/" + path
	}
	path = filepath.Clean(path)
	if err := streamEncryptedFile(w, path, true, filepath.Base(path), key); err != nil {
		encryptAndSend(w, []byte("Not found"), key)
	}
}

func handleRootDelete(w http.ResponseWriter, path string, key []byte) {
	os.RemoveAll(path)
	encryptAndSend(w, []byte("Deleted"), key)
}

func handleRootMkdir(w http.ResponseWriter, path string, key []byte) {
	os.MkdirAll(path, 0755)
	encryptAndSend(w, []byte("Directory created"), key)
}

func handleStats(w http.ResponseWriter, key []byte) {
	var s ServerStats
	s.OS = runtime.GOOS + " " + runtime.GOARCH
	s.Uptime = time.Since(startTime).String()

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					s.MemTotal = strings.TrimSpace(line[9:])
				}
				if strings.HasPrefix(line, "MemAvailable:") {
					s.MemFree = strings.TrimSpace(line[13:])
				}
			}
		}
	}
	out, _ := runShellCommand("df -h . | tail -1")
	fields := strings.Fields(string(out))
	if len(fields) >= 4 {
		s.DiskTotal, s.DiskUsed, s.DiskFree = fields[1], fields[2], fields[3]
	}

	data, _ := json.Marshal(s)
	encryptAndSend(w, data, key)
}

func generateThumbnail(fp string, id int64) {
	// Добавляем небольшую задержку, чтобы ОС успела полностью освободить файл после записи
	time.Sleep(500 * time.Millisecond)
	log.Printf("DEBUG: Generating thumbnail for file: %s", fp)
	img, err := imaging.Open(fp)
	if err != nil {
		log.Printf("THUMB_ERROR: [ID %d] Failed to open image %s: %v", id, fp, err)
		return
	}

	// Генерируем превью 200x200
	thumb := imaging.Fill(img, 200, 200, imaging.Center, imaging.Lanczos)

	// Используем thumbDir из globals.go
	os.MkdirAll(thumbDir, 0755)
	savePath := filepath.Join(thumbDir, fmt.Sprintf("thumb_%d.jpg", id))

	err = imaging.Save(thumb, savePath)
	if err != nil {
		log.Printf("THUMB_ERROR: [ID %d] Failed to save thumbnail to %s: %v", id, savePath, err)
		return
	}

	_, err = db.Exec("UPDATE files SET has_thumb = 1 WHERE id = ?", id)
	if err != nil {
		log.Printf("THUMB_ERROR: Failed to update DB for ID %d: %v", id, err)
	} else {
		log.Printf("DEBUG: Thumbnail generated successfully for ID %d", id)
	}
}

func encryptAndSend(w http.ResponseWriter, data []byte, key []byte) {
	iv := make([]byte, 16)
	rand.Read(iv)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Encryption-IV", hex.EncodeToString(iv))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("ERROR: Failed to create cipher for response: %v", err)
		return
	}
	stream := cipher.NewCTR(block, iv)

	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	w.Write(encrypted)
}
