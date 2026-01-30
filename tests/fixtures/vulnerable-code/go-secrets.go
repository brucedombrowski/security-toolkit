package main

// Test fixture with intentional secrets for scanner verification.
// All secrets use TEST patterns to avoid GitHub push protection.

import "fmt"

// Hardcoded credentials
const (
	DatabaseUser     = "admin"
	DatabasePassword = "super_secret_password_123"
	APIKey           = "api_key_test_1234567890abcdef"
)

// Bearer token (test pattern)
var (
	token := "Bearer ghp_TESTTOKE00000000000000000000000000"
)

// Connection string with credentials
func GetConnectionString() string {
	return "postgres://admin:MyDBPassword456@localhost:5432/production?sslmode=disable"
}

// AWS-style credentials (example patterns)
var awsConfig = map[string]string{
	"AccessKeyId":     "AKIAIOSFODNN7EXAMPLE",
	"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

func main() {
	fmt.Println("This is a test fixture with intentional secrets")
}
