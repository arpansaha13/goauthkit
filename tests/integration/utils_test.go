package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/arpansaha13/goauthkit/domain"
	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/goauthkit/utils"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TestFixture struct {
	T          *testing.T
	Ctx        context.Context
	DB         *pgxpool.Pool
	HTTPClient *HTTPTestHelper
	AuthClient pb.AuthServiceClient
	TestDB     *TestDB
}

// TableDrivenTestCase represents a single test case in a table-driven test
type TableDrivenTestCase struct {
	Name        string
	Setup       func(*TestFixture) error // Setup creates test data
	Test        func(*TestFixture) error // Test executes the test logic
	Verify      func(*TestFixture) error // Verify checks the results
	ExpectError bool                     // ExpectError indicates if an error is expected
	ErrMsg      string                   // ErrMsg is the expected error message (optional)
}

// NewTestFixture creates a new test fixture for a test
func NewTestFixture(t *testing.T, db *pgxpool.Pool, httpServerAddr string, authClient pb.AuthServiceClient) *TestFixture {
	httpHelper := NewHTTPTestHelper(httpServerAddr)
	return &TestFixture{
		T:          t,
		Ctx:        context.Background(),
		DB:         db,
		HTTPClient: httpHelper,
		AuthClient: authClient,
		TestDB:     NewTestDB(context.Background(), db),
	}
}

// TestDB holds database connection and repositories
type TestDB struct {
	Ctx    context.Context
	DB     *pgxpool.Pool
	Hasher *utils.PasswordHasher
}

// NewTestDB creates a new test database wrapper
func NewTestDB(ctx context.Context, db *pgxpool.Pool) *TestDB {
	return &TestDB{
		Ctx:    ctx,
		DB:     db,
		Hasher: utils.NewPasswordHasher(),
	}
}

// CreateTestUser creates a test user
func (t *TestDB) CreateTestUser(email, password string, verified bool) (*domain.User, error) {
	hashedPassword, err := t.Hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		Email:    email,
		Verified: verified,
		Credentials: &domain.Credentials{
			PasswordHash: hashedPassword,
		},
	}

	err = t.DB.QueryRow(t.Ctx, `
		INSERT INTO users (email, username, verified, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id, created_at`,
		user.Email, user.Username, user.Verified,
	).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	_, err = t.DB.Exec(t.Ctx, `INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)`, user.ID, hashedPassword)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateTestOTP creates a test OTP
func (t *TestDB) CreateTestOTP(userID int64, code string) (string, error) {
	otpHash, _ := utils.GenerateToken(32)
	hashedCode, err := t.Hasher.Hash(code)
	if err != nil {
		return "", err
	}

	otp := &domain.OTP{
		UserID:     userID,
		OTPHash:    otpHash,
		HashedCode: hashedCode,
		Purpose:    domain.OTPPurposeSignupVerification,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	err = t.DB.QueryRow(t.Ctx, `
		INSERT INTO otps (user_id, otp_hash, hashed_code, purpose, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id`,
		otp.UserID, otp.OTPHash, otp.HashedCode, otp.Purpose, otp.ExpiresAt,
	).Scan(&otp.ID)
	if err != nil {
		return "", err
	}
	return otpHash, nil
}

// CreateTestSession creates a test session
func (t *TestDB) CreateTestSession(userID int64) (string, error) {
	token, _ := utils.GenerateToken(32)
	// Hash token using the same logic as AuthService (token + secret)
	// We use "test-secret" in setup_test.go
	hasher := sha256.New()
	hasher.Write([]byte(token + "test-secret-key-at-least-32-characters-long-ok"))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	session := &domain.Session{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := t.DB.QueryRow(t.Ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id`,
		session.UserID, session.TokenHash, session.ExpiresAt,
	).Scan(&session.ID)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (t *TestDB) InsertOTP(otp *domain.OTP) error {
	return t.DB.QueryRow(t.Ctx, `
		INSERT INTO otps (user_id, otp_hash, hashed_code, purpose, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id, created_at`,
		otp.UserID, otp.OTPHash, otp.HashedCode, otp.Purpose, otp.ExpiresAt,
	).Scan(&otp.ID, &otp.CreatedAt)
}

// HTTPTestHelper provides HTTP client functionality for tests
type HTTPTestHelper struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewHTTPTestHelper creates a new HTTP test helper
func NewHTTPTestHelper(baseURL string) *HTTPTestHelper {
	return &HTTPTestHelper{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{},
	}
}

// MakeRequest makes an HTTP request
func (h *HTTPTestHelper) MakeRequest(method, path string, body any, cookie *http.Cookie) (*http.Response, error) {
	url := h.BaseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}

	return h.HTTPClient.Do(req)
}

// POST makes a POST request
func (h *HTTPTestHelper) POST(path string, body any) (*http.Response, error) {
	return h.MakeRequest("POST", path, body, nil)
}

// POSTWithCookie makes a POST request with a cookie
func (h *HTTPTestHelper) POSTWithCookie(path string, body any, cookie *http.Cookie) (*http.Response, error) {
	return h.MakeRequest("POST", path, body, cookie)
}

// ReadResponseBody reads and unmarshals response body
func ReadResponseBody(resp *http.Response, v any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
