// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SessionData is the payload stored inside the session cookie.
type SessionData struct {
	Subject     string    `json:"sub"`
	DisplayName string    `json:"name"`
	AvatarURL   string    `json:"avatar,omitempty"`
	Groups      []string  `json:"groups,omitempty"`
	Role        string    `json:"role,omitempty"`
	ExpiresAt   time.Time `json:"exp"`
}

// SessionManager encrypts/decrypts session cookies using AES-GCM.
type SessionManager struct {
	cookieName string
	maxAge     int
	secure     bool
	gcm        cipher.AEAD
}

// NewSessionManager creates a SessionManager.  key must be exactly 32 or 64
// bytes long; a 32-byte key selects AES-256-GCM.
func NewSessionManager(cookieName string, maxAgeSecs int, key string, secure bool) (*SessionManager, error) {
	k := []byte(key)
	if len(k) != 32 && len(k) != 64 {
		return nil, errors.New("session cookie encryption key must be 32 or 64 bytes")
	}
	// For a 64-byte key we use the first 32 bytes for AES-256.
	if len(k) == 64 {
		k = k[:32]
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &SessionManager{
		cookieName: cookieName,
		maxAge:     maxAgeSecs,
		secure:     secure,
		gcm:        gcm,
	}, nil
}

// SetSession serialises the UserIdentity, encrypts it, and writes the
// session cookie to w.
func (sm *SessionManager) SetSession(w http.ResponseWriter, identity *UserIdentity) error {
	data := SessionData{
		Subject:     identity.Subject,
		DisplayName: identity.DisplayName,
		AvatarURL:   identity.AvatarURL,
		Groups:      identity.Groups,
		Role:        identity.Role,
		ExpiresAt:   time.Now().Add(time.Duration(sm.maxAge) * time.Second),
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	encrypted, err := sm.encrypt(payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    base64.URLEncoding.EncodeToString(encrypted),
		Path:     "/",
		MaxAge:   sm.maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sm.secure,
	})
	return nil
}

// GetSession reads and decrypts the session cookie from r, returning the
// SessionData or an error if the cookie is missing, tampered, or expired.
func (sm *SessionManager) GetSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(sm.cookieName)
	if err != nil {
		return nil, errors.New("session cookie not found")
	}
	raw, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("session cookie is not valid base64: %w", err)
	}
	plaintext, err := sm.decrypt(raw)
	if err != nil {
		return nil, fmt.Errorf("session cookie decryption failed: %w", err)
	}
	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("session cookie payload is invalid JSON: %w", err)
	}
	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session has expired")
	}
	return &data, nil
}

// ClearSession removes the session cookie.
func (sm *SessionManager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// encrypt seals plaintext using AES-GCM and returns nonce||ciphertext.
func (sm *SessionManager) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, sm.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := sm.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt extracts the nonce from nonce||ciphertext and opens the AES-GCM seal.
func (sm *SessionManager) decrypt(data []byte) ([]byte, error) {
	ns := sm.gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	return sm.gcm.Open(nil, nonce, ciphertext, nil)
}
