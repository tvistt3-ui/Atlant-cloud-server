package main

import (
	"database/sql"
	"sync"
	"time"
)

const (
	workingDir = "./app_data"
	storageDir = "storage"
	thumbDir   = "storage/thumbs"
	dbFile     = "cloud.db"
	configFile = "config.json"

	// Quotas for memory keys (10GB per user)
	userQuotaBytes = 10 * 1024 * 1024 * 1024 // 10GB
)

var (
	db            *sql.DB
	conf          Config
	nonceCache    map[string]time.Time
	nonceMutex    sync.Mutex
	nonceTTL      = 5 * time.Minute
	memoryKeys    map[string]string // Map of Secure ID -> Full Memory Key
	memoryKeysMux sync.Mutex
	startTime     time.Time
)
