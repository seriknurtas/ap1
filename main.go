package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(2, 2)
var logger *logrus.Logger
var db *sql.DB

// Initialize logger
func initLogger() {
	logger = logrus.New()

	// Setup JSON formatter
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Open file for logging
	file, err := os.OpenFile("log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	// Write logs to both file and stdout
	logger.SetOutput(io.MultiWriter(file, os.Stdout))
	logger.SetLevel(logrus.InfoLevel)

	logger.Info("Logger initialized. Logs will be written to log.txt and stdout")
}

// Initialize database
func initDB() {
	var err error
	connStr := "user=postgres password=12345 dbname=contacts sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.WithFields(logrus.Fields{"action": "initDB", "status": "failed", "error": err.Error()}).Fatal("Failed to connect to the database")
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS contacts (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100),
		email VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		logger.WithFields(logrus.Fields{"action": "initDB", "status": "failed", "error": err.Error()}).Fatal("Failed to create table")
	}

	logger.WithFields(logrus.Fields{"action": "initDB", "status": "success"}).Info("Database initialized successfully")
}

// Error handler
func handleError(w http.ResponseWriter, status int, message string, err error) {
	w.WriteHeader(status)
	response := map[string]string{"error": message}
	if err != nil {
		logger.WithFields(logrus.Fields{"status": status, "error": err.Error()}).Error(message)
		response["details"] = err.Error()
	} else {
		logger.WithFields(logrus.Fields{"status": status}).Error(message)
	}
	json.NewEncoder(w).Encode(response)
}

// Rate limiter middleware
func rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			handleError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please wait and try again.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CORS middleware
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Contact struct
type Contact struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Handlers for CRUD operations
func createContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		return
	}

	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	var nextID int
	err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM contacts`).Scan(&nextID)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to calculate next ID", err)
		return
	}

	query := `INSERT INTO contacts (id, name, email, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	_, err = db.Exec(query, nextID, contact.Name, contact.Email)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to create contact", err)
		return
	}

	logger.WithFields(logrus.Fields{"action": "createContact", "name": contact.Name, "email": contact.Email}).Info("Contact created successfully")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact created successfully"})
}

func getContactsHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sort := r.URL.Query().Get("sort")
	page := r.URL.Query().Get("page")
	limit := 10
	offset := 0

	if p, err := strconv.Atoi(page); err == nil && p > 0 {
		offset = (p - 1) * limit
	}

	query := "SELECT id, name, email, created_at, updated_at FROM contacts"
	var conditions []string
	var args []interface{}

	if filter != "" {
		conditions = append(conditions, "name ILIKE $1")
		args = append(args, "%"+filter+"%")
	}

	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			query += " AND " + conditions[i]
		}
	}

	if sort != "" {
		allowedSortFields := map[string]bool{"name": true, "email": true, "created_at": true}
		if allowedSortFields[sort] {
			query += fmt.Sprintf(" ORDER BY %s", sort)
		} else {
			handleError(w, http.StatusBadRequest, "Invalid sort field", nil)
			return
		}
	}

	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to fetch contacts", err)
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		if err := rows.Scan(&contact.ID, &contact.Name, &contact.Email, &contact.CreatedAt, &contact.UpdatedAt); err != nil {
			handleError(w, http.StatusInternalServerError, "Failed to parse contacts", err)
			return
		}
		contacts = append(contacts, contact)
	}

	logger.WithFields(logrus.Fields{"action": "getContacts", "filter": filter, "sort": sort, "page": page}).Info("Contacts fetched successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contacts)
}

// Update contact
func updateContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		return
	}

	id := r.URL.Path[len("/contacts/"):]
	if id == "" {
		handleError(w, http.StatusBadRequest, "Missing contact ID", nil)
		return
	}

	contactID, err := strconv.Atoi(id)
	if err != nil {
		handleError(w, http.StatusBadRequest, "Invalid contact ID", err)
		return
	}

	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	query := `UPDATE contacts SET name = $1, email = $2, updated_at = NOW() WHERE id = $3`
	_, err = db.Exec(query, contact.Name, contact.Email, contactID)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to update contact", err)
		return
	}

	logger.WithFields(logrus.Fields{"action": "updateContact", "id": contactID, "name": contact.Name, "email": contact.Email}).Info("Contact updated successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact updated successfully"})
}

// Delete contact
func deleteContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		handleError(w, http.StatusBadRequest, "Missing contact ID", nil)
		return
	}

	query := `DELETE FROM contacts WHERE id = $1`
	_, err := db.Exec(query, id)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to delete contact", err)
		return
	}

	logger.WithFields(logrus.Fields{"action": "deleteContact", "id": id}).Info("Contact deleted successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact deleted successfully"})
}

// Update and delete handlers are similar...

func main() {
	initLogger()
	initDB()
	defer db.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("/contacts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getContactsHandler(w, r)
		case http.MethodPost:
			createContactHandler(w, r)
		case http.MethodDelete:
			deleteContactHandler(w, r)
		default:
			handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		}
	})

	mux.HandleFunc("/contacts/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			updateContactHandler(w, r)
		default:
			handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		}
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: enableCORS(rateLimit(mux)),
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("Server is starting...")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	<-quit
	logger.Info("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited gracefully")
}
