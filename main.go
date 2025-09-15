package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync/atomic"

	"database/sql"
	"os"
	"time"

	"github.com/demola07/chirpy/internal/auth"

	"github.com/google/uuid"

	"github.com/demola07/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type UpgradeEvent struct {
	Event string      `json:"event"`
	Data  UpgradeData `json:"data"`
}

type UpgradeData struct {
	UserID string `json:"user_id"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1) // increment counter
		next.ServeHTTP(w, r)      // call the next handler
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	count := cfg.fileserverHits.Load()

	html := fmt.Sprintf(`
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	</html>`, count)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		log.Printf("handle reset error: %s", cfg.platform)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := cfg.db.DeleteAllUsers(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete users")
		return
	}

	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("All users deleted, hits reset to 0"))
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

type chirpRequest struct {
	Body   string `json:"body"`
	UserID string `json:"user_id"`
}

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, errorResponse{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func (cfg *apiConfig) handlerChirp(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	var chirp chirpRequest
	err = decoder.Decode(&chirp)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	// validate chirp length
	if len(chirp.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	// userID, err := uuid.Parse(chirp.UserID)
	// if err != nil {
	// 	respondWithError(w, http.StatusBadRequest, "Invalid user ID")
	// 	return
	// }

	dbChirp, err := cfg.db.CreateChirpy(r.Context(), database.CreateChirpyParams{
		Body:   chirp.Body,
		UserID: userID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create chirp")
		return
	}

	apiChirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}

	respondWithJSON(w, http.StatusCreated, apiChirp)
}

func (cfg *apiConfig) fetchChirps(w http.ResponseWriter, r *http.Request) {
	var chirps []database.Chirpy
	var err error

	// Check if author_id filter is provided
	if s := r.URL.Query().Get("author_id"); s != "" {
		authorID, parseErr := uuid.Parse(s)
		if parseErr != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid author_id")
			return
		}
		// Fetch chirps by specific author
		chirps, err = cfg.db.ListChirpyByAuthor(r.Context(), authorID)
	} else {
		// Fetch all chirps
		chirps, err = cfg.db.ListChirpy(r.Context())
	}
	if err != nil {
		log.Printf("Error fetching chirps: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not fetch chirps")
		return
	}

	sortOrder := r.URL.Query().Get("sort")
	if sortOrder == "" {
		sortOrder = "asc"
	}

	sort.Slice(chirps, func(i, j int) bool {
		if sortOrder == "desc" {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		}
		return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
	})

	// Map DB rows → response type
	resCh := make([]Chirp, len(chirps))
	for i, chirp := range chirps {
		resCh[i] = Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
	}

	respondWithJSON(w, http.StatusOK, resCh)
}

func (cfg *apiConfig) fetchChirp(w http.ResponseWriter, r *http.Request) {
	// Extract chirpID from URL
	// For simplicity, assuming URL is /api/chirps/{chirpID}
	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.db.GetChirpyByID(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			log.Printf("Error fetching chirp: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not fetch chirp")
		}
		return
	}

	apiChirp := Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	respondWithJSON(w, http.StatusOK, apiChirp)
}

// helper: marshal + write
// func writeJSON(w http.ResponseWriter, status int, resp interface{}) {
// 	dat, err := json.Marshal(resp)
// 	if err != nil {
// 		log.Printf("Error marshalling JSON: %s", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(status)
// 	w.Write(dat)
// }

// Another version of the handler using json.Encoder

// func HandleValidateChirp(w http.ResponseWriter, r *http.Request) {
// 	// Only allow POST
// 	if r.Method != http.MethodPost {
// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 		json.NewEncoder(w).Encode(errorResponse{Error: "Method not allowed"})
// 		return
// 	}

// 	var req chirpRequest
// 	err := json.NewDecoder(r.Body).Decode(&req)
// 	if err != nil {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
// 		return
// 	}

// 	if len(req.Body) > 140 {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(errorResponse{Error: "Chirp is too long"})
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(validResponse{Valid: true})
// }

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	// 1. Extract refresh token from Authorization header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid refresh token")
		return
	}

	// 2. Look up refresh token in DB
	dbUserRefreshToken, err := cfg.db.RetrieveToken(r.Context(), refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid refresh token")
		} else {
			log.Printf("Error fetching refresh token: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not verify refresh token")
		}
		return
	}

	// 3. Check expiry
	if time.Now().UTC().After(dbUserRefreshToken.ExpiresAt) {
		respondWithError(w, http.StatusUnauthorized, "Refresh token expired")
		return
	}

	// 4. Generate new access token (1 hour)
	accessToken, err := auth.MakeJWT(dbUserRefreshToken.UserID, cfg.jwtSecret, time.Hour)
	if err != nil {
		log.Printf("Error creating access token: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create access token")
		return
	}

	// 5. Send response
	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": accessToken,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	// 1. Get refresh token from headers
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid refresh token")
		return
	}

	// 2. Revoke token
	err = cfg.db.RevokeToken(r.Context(), refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid refresh token")
		} else {
			log.Printf("Error revoking token: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not revoke refresh token")
		}
		return
	}

	// 3. Success — 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func dbUserToAPIUser(dbUser database.User, token string, refreshToken string) User {
	return User{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  dbUser.IsChirpyRed,
	}
}

func (cfg *apiConfig) handlerLoginUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var req userRequest
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	dbUser, err := cfg.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No user found with email: %s", req.Email)
			respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		} else {
			log.Printf("Error fetching user: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not fetch user")
		}
		return
	}

	err = auth.CheckPasswordHash(req.Password, dbUser.HashedPassword)
	if err != nil {
		log.Printf("Password mismatch for user: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	expiresIn := time.Hour
	token, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, expiresIn)
	if err != nil {
		log.Printf("Error generating JWT: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not generate token")
		return
	}

	// --- Generate refresh token (60 days) ---
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not create refresh token")
		return
	}

	expiresAt := time.Now().UTC().Add(60 * 24 * time.Hour) // 60 days

	// Save refresh token in DB
	savedRefreshToken, err := cfg.db.CreateToken(r.Context(), database.CreateTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: expiresAt,
		RevokedAt: sql.NullTime{Valid: false},
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not save refresh token")
		return
	}

	apiUser := dbUserToAPIUser(dbUser, token, savedRefreshToken.Token)
	respondWithJSON(w, http.StatusOK, apiUser)
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var req userRequest
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Hash the password before storing
	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong!! Please try again")
		return
	}

	dbUser, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		log.Printf("Error creating user: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	apiUser := dbUserToAPIUser(dbUser, "", "")
	respondWithJSON(w, http.StatusCreated, apiUser)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	var req userRequest
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong!! Please try again")
		return
	}

	updatedUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	})
	if err != nil {
		log.Printf("Error updating user: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not update user")
		return
	}

	apiUser := dbUserToAPIUser(updatedUser, "", "")
	respondWithJSON(w, http.StatusOK, apiUser)

}

func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
		return
	}

	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.db.GetChirpyByID(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			log.Printf("Error getting chirp: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not get chirp")
		}
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "You don't have permission to delete this chirp")
		return
	}

	err = cfg.db.DeleteChirpyByID(r.Context(), database.DeleteChirpyByIDParams{
		ID:     chirpID,
		UserID: userID,
	})
	if err != nil {
		log.Printf("Error deleting chirp: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not delete chirp")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleUpgradeUser(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var event UpgradeEvent
	if err := decoder.Decode(&event); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if event.Event != "user.upgraded" {
		respondWithError(w, http.StatusNoContent, "cannot handle event")
		return
	} else if event.Event == "user.upgraded" {
		userID, err := uuid.Parse(event.Data.UserID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}
		_, err = cfg.db.UpgradeUserToRed(r.Context(), userID)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "User not found")
			} else {
				log.Printf("Error upgrading user: %s", err)
				respondWithError(w, http.StatusInternalServerError, "Could not upgrade user")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	JWT_SECRET := os.Getenv("JWT_SECRET")
	platform := os.Getenv("PLATFORM")
	POLKA_KEY := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Cannot connect to db:", err)
	}
	defer db.Close()
	dbQueries := database.New(db)

	mux := http.NewServeMux()

	apiCfg := &apiConfig{
		db:        dbQueries,
		platform:  platform,
		jwtSecret: JWT_SECRET,
		polkaKey:  POLKA_KEY,
	}

	fileServer := http.FileServer(http.Dir("."))

	mux.HandleFunc("GET /api/healthz", httpHandler)

	// mux.Handle("/app/", http.StripPrefix("/app/", fileServer))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fileServer)))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	// Metrics endpoint
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	// Reset endpoint
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)

	// mux.HandleFunc("/api/validate_chirp", handlerValidateChirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.fetchChirps)
	mux.HandleFunc(("GET /api/chirps/{chirpID}"), apiCfg.fetchChirp)

	mux.HandleFunc("POST /api/users", apiCfg.handlerCreateUser)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)

	mux.HandleFunc(("POST /api/login"), apiCfg.handlerLoginUser)

	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleDeleteChirp)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleUpgradeUser)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}

}
