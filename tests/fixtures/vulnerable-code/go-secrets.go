// Test Fixture: Go file with intentional secrets for scanner detection.
// This file is used by integration tests to verify secret detection.
// DO NOT use these credentials - they are fake test data.

package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Hardcoded credentials (should be detected)
const (
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	DatabasePassword   = "super_secret_db_pass_123"
	APIKey             = "sk-proj-TESTKEY00000000000000000000000000000000000000"
)

// Connection string with embedded credentials (should be detected)
var dbConnectionString = "postgres://admin:MyPassword123@localhost:5432/mydb?sslmode=disable"

// Private key embedded in code (should be detected)
var privateKey = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKvU9KCXgAL8L4cD8v3c5E8dJkRJlvFiQBf3N...
-----END EC PRIVATE KEY-----`

func connectDatabase() (*sql.DB, error) {
	// Inline password (should be detected)
	password := "hardcoded_password_456"
	connStr := fmt.Sprintf("user=root password=%s dbname=test", password)
	return sql.Open("postgres", connStr)
}

func makeAPIRequest() (*http.Response, error) {
	// API token in header (should be detected - test pattern)
	token := "Bearer ghp_TESTTOKEN00000000000000000000000000"
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", token)
	return http.DefaultClient.Do(req)
}

func main() {
	fmt.Println("This is a test fixture for secret detection")
}
