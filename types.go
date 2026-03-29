package main


type Config struct {
	Port      string `json:"port"`
	UserQuota int64  `json:"user_quota_bytes"` // Default quota per memory key (10GB = 10737418240)
}

type UserQuotaInfo struct {
	MemoryKey      string
	UsedBytes      int64
	QuotaBytes     int64
	CanUpload      bool
	RemainingBytes int64
	Role          string // Добавлено: роль пользователя
}

type EncryptedRequest struct {
	Token     string `json:"token"`      // Only used if this is a full ApiToken request
	KeyID     string `json:"key_id"`     // ПУБЛИЧНЫЙ идентификатор ключа (для поиска MemoryKey на сервере)
	MemoryKey string `json:"memory_key"` // Limited access key (alternative to Token)
	Command   string `json:"command"`    // "list", "stats", "exec", "thumb", "delete", "generate_key"
	Param     string `json:"param"`
	Nonce     string `json:"nonce"`
}

// Nonce is a client-provided one-time identifier to prevent replay attacks
type NonceEntry struct{}

type FileRecord struct {
	ID        int    `json:"id"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	Created   string `json:"created"`
	Thumbnail string `json:"thumbnail,omitempty"`
	OwnerKey  string `json:"owner_key,omitempty"` // Memory key that owns this file
	Is_dir    bool   `json:"is_dir"`              // Added: for folders support
	Name      string `json:"name,omitempty"`      // Added: for folder name
}

type RootFileInfo struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Path  string `json:"path"`
}

type ServerStats struct {
	CPUUsage  string `json:"cpu_usage"`
	MemTotal  string `json:"mem_total"`
	MemFree   string `json:"mem_free"`
	DiskTotal string `json:"disk_total"` // Добавлено
	DiskUsed  string `json:"disk_used"`  // Добавлено
	DiskFree  string `json:"disk_free"`
	Uptime    string `json:"uptime"`
	OS        string `json:"os"`
}
