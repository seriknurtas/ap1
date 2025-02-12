package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	"google.golang.org/api/gmail/v1"
)

var (
	limiter           = rate.NewLimiter(2, 2)
	db                *sql.DB
	logger            *logrus.Logger
	jwtKey            = []byte("supersecretkey")
	googleOauthConfig *oauth2.Config
)

type User struct {
	ID               int    `json:"id"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	Role             string `json:"role"`
	Verified         bool   `json:"verified"`
	VerificationCode string `json:"verification_code"`
}

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

func initLogger() {
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	file, err := os.OpenFile("log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger.SetOutput(io.MultiWriter(file, os.Stdout))
	logger.SetLevel(logrus.InfoLevel)
	logger.Info("Logger initialized. Logs will be written to log.txt and stdout")
}

func initDB() {
	var err error
	connStr := "user=postgres password=12345 dbname=contacts sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.Fatal("Failed to connect to the database", err)
	}

	// Создаём таблицу пользователей
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(100) UNIQUE,
		role VARCHAR(20) DEFAULT 'user',
		verified BOOLEAN DEFAULT TRUE
	)`)
	if err != nil {
		logger.Fatal("Failed to create users table", err)
	}

	// Создаём таблицу контактов
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS contacts (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100),
		email VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		logger.Fatal("Failed to create contacts table", err)
	}

	logger.Info("Database initialized successfully")
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func comparePasswords(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

func generateVerificationCode() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func loadGoogleCredentials() error {
	if googleOauthConfig != nil {
		return nil // Конфигурация уже загружена
	}

	b, err := os.ReadFile("credentials.json")
	if err != nil {
		return fmt.Errorf("unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b,
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/gmail.send", // ✅ Теперь email можно отправлять
	)
	if err != nil {
		return fmt.Errorf("unable to parse client secret file: %v", err)
	}

	config.RedirectURL = "http://localhost:8080/auth/google/callback" // Добавляем вручную
	googleOauthConfig = config
	return nil
}
func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("oauthstate")
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	client := googleOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	var existingUser struct {
		ID    int
		Email string
		Role  string
	}
	err = db.QueryRow("SELECT id, email, role FROM users WHERE email = $1", userInfo.Email).
		Scan(&existingUser.ID, &existingUser.Email, &existingUser.Role)

	if err == sql.ErrNoRows {
		_, err = db.Exec("INSERT INTO users (email, role, verified) VALUES ($1, 'user', true)", userInfo.Email)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		existingUser.Email = userInfo.Email
		existingUser.Role = "user"
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: existingUser.Email,
		Role:  existingUser.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Send token as Authorization header
	w.Header().Set("Authorization", "Bearer "+tokenString)
	w.WriteHeader(http.StatusOK)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	userRole, ok := r.Context().Value("role").(string)
	if !ok || userRole != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	http.ServeFile(w, r, "admin.html") // Отправляем страницу админки
}

type AdminUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// Проверка прав администратора
func isAdmin(role string) bool {
	return role == "admin"
}

// Получение списка пользователей (только для админа)
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("role").(string)
	if !isAdmin(userRole) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rows, err := db.Query("SELECT id, email, role FROM users")
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []AdminUser
	for rows.Next() {
		var user AdminUser
		if err := rows.Scan(&user.ID, &user.Email, &user.Role); err != nil {
			http.Error(w, "Failed to scan users", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Удаление пользователя (только для админа)
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("role").(string)
	if !isAdmin(userRole) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing user ID", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

// Изменение роли пользователя (только для админа)
func updateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("role").(string)
	if !isAdmin(userRole) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var request struct {
		UserID int    `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.Role != "admin" && request.Role != "user" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE users SET role = $1 WHERE id = $2", request.Role, request.UserID)
	if err != nil {
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User role updated successfully"})
}

func authMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Authorization")
			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Проверяем роль пользователя
			if requiredRole != "" && claims.Role != requiredRole {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Добавляем роль в контекст запроса
			ctx := context.WithValue(r.Context(), "role", claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Error hashing password", err)
		return
	}

	verificationCode := generateVerificationCode()
	_, err = db.Exec("INSERT INTO users (email, password, role, verified, verification_code) VALUES ($1, $2, 'user', FALSE, $3)",
		user.Email, hashedPassword, verificationCode)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Error creating user", err)
		return
	}

	err = sendVerificationEmail(user.Email, verificationCode)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to send verification email", err)
		return
	}

	log.Printf("Verification code sent to email: %s", verificationCode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered, check email for verification code"})
}

func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedCode string
	err := db.QueryRow("SELECT verification_code FROM users WHERE email = $1", request.Email).Scan(&storedCode)
	if err != nil {
		http.Error(w, "Invalid email or code", http.StatusUnauthorized)
		return
	}

	if storedCode != request.Code {
		http.Error(w, "Invalid verification code", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec("UPDATE users SET verified = TRUE, verification_code = NULL WHERE email = $1", request.Email)
	if err != nil {
		http.Error(w, "Error updating verification status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
}

// Отправка email с кодом подтверждения через Gmail API
func sendVerificationEmail(to, code string) error {
	emailBody := fmt.Sprintf("Ваш код подтверждения: %s", code)
	message := &gmail.Message{
		Raw: encodeWeb64String(fmt.Sprintf("To: %s\r\nSubject: Email Verification\r\n\r\n%s", to, emailBody)),
	}

	_, err := gmailService.Users.Messages.Send("me", message).Do()
	if err != nil {
		return fmt.Errorf("не удалось отправить email: %v", err)
	}
	return nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	var credentials User
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, email, password, role, verified FROM users WHERE email = $1", credentials.Email).
		Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.Verified)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	if !comparePasswords(user.Password, credentials.Password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	if !user.Verified {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email not verified"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: user.Email,
		Role:  user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
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
func getContactByIDHandler(w http.ResponseWriter, r *http.Request) {
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
	err = db.QueryRow(`SELECT id, name, email, created_at, updated_at FROM contacts WHERE id = $1`, contactID).
		Scan(&contact.ID, &contact.Name, &contact.Email, &contact.CreatedAt, &contact.UpdatedAt)
	if err == sql.ErrNoRows {
		handleError(w, http.StatusNotFound, "Contact not found", nil)
		return
	} else if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to fetch contact", err)
		return
	}

	logger.WithFields(logrus.Fields{"action": "getContactByID", "id": contactID}).Info("Contact fetched successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contact)
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
func getToken(config *oauth2.Config) (*oauth2.Token, error) {
	tokenFile := "token.json"
	token, err := tokenFromFile(tokenFile)
	if err != nil {
		// Если токена нет в файле, запрашиваем у пользователя
		return getTokenFromWeb(config), nil
	}

	// Проверяем, не истёк ли токен
	if token.Expiry.Before(time.Now()) {
		log.Println("Access token expired, refreshing...")
		newToken, err := config.TokenSource(context.Background(), token).Token()
		if err != nil {
			return nil, fmt.Errorf("unable to refresh token: %v", err)
		}
		saveToken(tokenFile, newToken)
		return newToken, nil
	}
	return token, nil
}

func GetClient(config *oauth2.Config) *http.Client {
	token, err := getToken(config)
	if err != nil {
		log.Fatalf("Failed to retrieve token: %v", err)
	}
	return config.Client(context.Background(), token)
}

// Читаем токен из файла
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

// Запрашиваем новый токен через веб-авторизацию
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser and enter the authorization code: \n%v\n", authURL)

	var authCode string
	fmt.Print("Enter the authorization code: ")
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	token, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	saveToken("token.json", token)
	return token
}

// Сохраняем новый токен в файл
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Unable to cache OAuth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// SendEmail sends an email using the Gmail API.
func SendEmail(service *gmail.Service, to string, subject string, rawMessage string) error {
	// Кодируем email в base64 URL-safe
	message := &gmail.Message{
		Raw: encodeWeb64String(rawMessage),
	}

	_, err := service.Users.Messages.Send("me", message).Do()
	if err != nil {
		return fmt.Errorf("unable to send email: %v", err)
	}
	return nil
}

// Encodes a string to base64 web-safe encoding.
func encodeWeb64String(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}
func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
		return
	}

	var request struct {
		Subject string `json:"subject"`
		Message string `json:"message"`
		Image   string `json:"image"` // Base64 закодированное изображение
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	to := "funroyale198@gmail.com" // Email получателя

	// Формируем заголовки письма
	emailHeaders := fmt.Sprintf("To: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n", to, request.Subject)

	if request.Image != "" {
		// Если есть изображение, добавляем вложение
		emailHeaders += "Content-Type: multipart/mixed; boundary=boundary123\r\n\r\n"
		emailHeaders += "--boundary123\r\n"
		emailHeaders += "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
		emailHeaders += request.Message + "\r\n\r\n"
		emailHeaders += "--boundary123\r\n"
		emailHeaders += "Content-Type: image/png\r\n"
		emailHeaders += "Content-Transfer-Encoding: base64\r\n"
		emailHeaders += "Content-Disposition: attachment; filename=\"image.png\"\r\n\r\n"
		emailHeaders += request.Image + "\r\n"
		emailHeaders += "--boundary123--"
	} else {
		// Если нет изображения, отправляем обычное письмо
		emailHeaders += "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
		emailHeaders += request.Message
	}

	// Отправка email через Gmail API
	err := SendEmail(gmailService, to, request.Subject, emailHeaders)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to send email", err)
		return
	}

	logger.WithFields(logrus.Fields{"action": "sendEmail", "subject": request.Subject}).Info("Email sent successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email sent successfully!"})
}
func setupAdminRoutes(mux *http.ServeMux) {
	mux.Handle("/admin/users", authMiddleware("admin")(http.HandlerFunc(getUsersHandler)))
	mux.Handle("/admin/delete-user", authMiddleware("admin")(http.HandlerFunc(deleteUserHandler)))
	mux.Handle("/admin/update-role", authMiddleware("admin")(http.HandlerFunc(updateUserRoleHandler)))
}

var gmailService *gmail.Service

// Роуты сервера
func setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/verify-email", verifyEmailHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/auth/google/login", googleLoginHandler)
	mux.HandleFunc("/auth/google/callback", googleCallbackHandler)

	mux.Handle("/admin", authMiddleware("admin")(http.HandlerFunc(adminHandler)))
	mux.Handle("/contacts", authMiddleware("user")(http.HandlerFunc(contactsHandler)))
	mux.Handle("/contacts/", authMiddleware("user")(http.HandlerFunc(contactByIDHandler)))

}

func contactsHandler(w http.ResponseWriter, r *http.Request) {
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
}

func contactByIDHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getContactByIDHandler(w, r)
	case http.MethodPut:
		updateContactHandler(w, r)
	default:
		handleError(w, http.StatusMethodNotAllowed, "Invalid request method", nil)
	}
}

func main() {
	godotenv.Load()
	log.Println("Loading Google credentials...")
	if err := loadGoogleCredentials(); err != nil {
		log.Fatalf("Failed to load Google credentials: %v", err)
	}

	if googleOauthConfig == nil { // Проверяем, что конфигурация загружена
		log.Fatalf("Google OAuth config not loaded!")
	}

	log.Println("Initializing database...")
	initLogger()
	initDB()
	defer db.Close()

	// ✅ Инициализация Gmail API с использованием уже загруженного googleOauthConfig
	client := GetClient(googleOauthConfig)
	var err error
	gmailService, err = gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	mux := http.NewServeMux()
	setupRoutes(mux)
	setupAdminRoutes(mux)

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
