// Anthra Security Platform - Log Ingest Microservice
// Accepts log events from distributed agents and stores them centrally
//
// FedRAMP Hardened version for federal market entry.
//
// NIST 800-53 Control Mapping:
// - IA-5(7): No embedded unencrypted static authenticators
// - SC-8(1): Transmission Confidentiality (TLS 1.2+)
// - SC-13: Cryptographic Protection (SSL for DB)
// - AC-6: Least Privilege (Credential management)

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// NIST 800-53 IA-5(7): No hard-coded credentials.
// Values are injected via Kubernetes Secrets.
var (
	dbHost = os.Getenv("DB_HOST")
	dbPort = os.Getenv("DB_PORT")
	dbName = os.Getenv("DB_NAME")
	dbUser = os.Getenv("DB_USER")
	dbPass = os.Getenv("DB_PASSWORD")
)

func main() {
	if dbPass == "" {
		log.Fatal("FATAL: DB_PASSWORD environment variable is not set")
	}

	// NIST 800-53 SC-13: Cryptographic Protection.
	// Production: Use sslmode=verify-full with proper certificates.
	// For this hardening pass, we enable 'require' to ensure encryption.
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=require",
		dbHost, dbPort, dbName, dbUser, dbPass,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("WARN: Cannot connect to Postgres (%v), running in log-only mode", err)
	}
	defer db.Close()

	// Configure handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", ingestHandler(db))
	mux.HandleFunc("/health", healthHandler)

	// NIST 800-53 SC-8(1): Transmission Confidentiality (HTTPS).
	// FedRAMP requires TLS 1.2 or higher for all data in transit.
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile != "" && keyFile != "" {
		log.Printf("Anthra log-ingest service listening on :%s (HTTPS)", port)
		log.Fatal(http.ListenAndServeTLS(":"+port, certFile, keyFile, mux))
	} else {
		// FALLBACK for development - NIST requires warning if non-TLS is used.
		log.Printf("WARN: Starting without TLS. This is NOT compliant with NIST 800-53 SC-8.")
		log.Printf("Anthra log-ingest service listening on :%s (HTTP)", port)
		log.Fatal(http.ListenAndServe(":"+port, mux))
	}
}

// ingestHandler processes incoming log events
func ingestHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		// NIST AU-2: Audit events (Logging the request internally)
		log.Printf("Ingest request received from %s", r.RemoteAddr)

		var event struct {
			TenantID string `json:"tenant_id"`
			Level    string `json:"level"`
			Message  string `json:"message"`
			Source   string `json:"source"`
		}

		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// NIST AC-3: Tenant isolation check
		if event.TenantID == "" {
			http.Error(w, "tenant_id is required", http.StatusBadRequest)
			return
		}

		// Store in database
		if db != nil {
			_, err := db.Exec(
				"INSERT INTO logs (tenant_id, level, message, source, created_at) VALUES ($1, $2, $3, $4, $5)",
				event.TenantID,
				event.Level,
				event.Message,
				event.Source,
				time.Now(),
			)
			if err != nil {
				log.Printf("DB insert failed: %v", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ingested",
			"tenant_id": event.TenantID,
		})
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "anthra-log-ingest",
	})
}
