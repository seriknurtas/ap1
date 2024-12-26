package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	_ "gorm.io/gorm"
)

func getContactByIDHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/contacts/"):]

	// Проверка, передан ли ID
	if id == "" {
		http.Error(w, "Missing contact ID", http.StatusBadRequest)
		return
	}

	contactID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid contact ID", http.StatusBadRequest)
		return
	}

	var contact Contact
	err = db.QueryRow(`SELECT id, name, email, created_at, updated_at FROM contacts WHERE id = $1`, contactID).
		Scan(&contact.ID, &contact.Name, &contact.Email, &contact.CreatedAt, &contact.UpdatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "Contact not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Failed to fetch contact", http.StatusInternalServerError)
		log.Println("Error fetching contact:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contact)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Обработка preflight-запроса
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type Contact struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var db *sql.DB

func initDB() {
	var err error
	connStr := "user=postgres password=12345 dbname=contacts sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS contacts (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100),
		email VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`) // Migration
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}
	log.Println("Database initialized successfully.")
}

func createContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Найти максимальный ID и вычислить следующий
	var nextID int
	err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM contacts`).Scan(&nextID)
	if err != nil {
		http.Error(w, "Failed to calculate next ID", http.StatusInternalServerError)
		log.Println("Error calculating next ID:", err)
		return
	}

	// Вставить запись с вычисленным ID
	query := `INSERT INTO contacts (id, name, email, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	_, err = db.Exec(query, nextID, contact.Name, contact.Email)
	if err != nil {
		http.Error(w, "Failed to create contact", http.StatusInternalServerError)
		log.Println("Error inserting contact:", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact created successfully"})
}

func getContactsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT id, name, email, created_at, updated_at FROM contacts`)
	if err != nil {
		http.Error(w, "Failed to fetch contacts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		if err := rows.Scan(&contact.ID, &contact.Name, &contact.Email, &contact.CreatedAt, &contact.UpdatedAt); err != nil {
			http.Error(w, "Failed to parse contacts", http.StatusInternalServerError)
			return
		}
		contacts = append(contacts, contact)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contacts)
}

func updateContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Извлекаем ID контакта из URL
	id := r.URL.Path[len("/contacts/"):]
	if id == "" {
		http.Error(w, "Missing contact ID", http.StatusBadRequest)
		return
	}

	// Парсим ID в целочисленное значение
	contactID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid contact ID", http.StatusBadRequest)
		return
	}

	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Проверяем, существует ли запись с данным ID
	var exists bool
	err = db.QueryRow(`SELECT EXISTS (SELECT 1 FROM contacts WHERE id = $1)`, contactID).Scan(&exists)
	if err != nil {
		http.Error(w, "Failed to check contact existence", http.StatusInternalServerError)
		log.Println("Error checking contact existence:", err)
		return
	}
	if !exists {
		http.Error(w, "Contact not found", http.StatusNotFound)
		return
	}

	// Обновляем запись
	query := `UPDATE contacts SET name = $1, email = $2, updated_at = NOW() WHERE id = $3`
	_, err = db.Exec(query, contact.Name, contact.Email, contactID)
	if err != nil {
		http.Error(w, "Failed to update contact", http.StatusInternalServerError)
		log.Println("Error updating contact:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact updated successfully"})
}

func deleteContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing contact ID", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM contacts WHERE id = $1`
	_, err := db.Exec(query, id)
	if err != nil {
		http.Error(w, "Failed to delete contact", http.StatusInternalServerError)
		return
	}

	// Сброс последовательности
	resetSeqQuery := `SELECT setval('contacts_id_seq', COALESCE(MAX(id), 1)) FROM contacts`
	_, err = db.Exec(resetSeqQuery)
	if err != nil {
		log.Println("Failed to reset sequence:", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact deleted successfully"})

}

func main() {
	initDB()
	defer db.Close()

	mux := http.NewServeMux()

	// Main route for contacts
	mux.HandleFunc("/contacts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getContactsHandler(w, r)
		case http.MethodPost:
			createContactHandler(w, r)
		case http.MethodDelete:
			deleteContactHandler(w, r)
		default:
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	})

	// Route for specific contact (search/update)
	mux.HandleFunc("/contacts/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getContactByIDHandler(w, r)
		case http.MethodPut:
			updateContactHandler(w, r)
		default:
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	})

	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", enableCORS(mux)))
}
