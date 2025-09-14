package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	secret := "mysecret"
	userID := uuid.New()

	// create token
	token, err := MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to make jwt: %v", err)
	}

	// validate token
	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("failed to validate jwt: %v", err)
	}

	if parsedID != userID {
		t.Errorf("expected %v, got %v", userID, parsedID)
	}
}

func TestExpiredJWT(t *testing.T) {
	secret := "mysecret"
	userID := uuid.New()

	// create token that expires immediately
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("failed to make jwt: %v", err)
	}

	// validate should fail
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("expected error for expired token, got none")
	}
}

func TestWrongSecretJWT(t *testing.T) {
	secret := "mysecret"
	wrongSecret := "wrongsecret"
	userID := uuid.New()

	// create token with correct secret
	token, err := MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to make jwt: %v", err)
	}

	// validate with wrong secret should fail
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Error("expected error for invalid secret, got none")
	}
}
