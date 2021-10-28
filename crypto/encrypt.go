// Package crypto is a wrapper on the built-in *crypto/bcrypt* package, but with
// an easier interface to encrypt passwords and validate an input password.
package crypto

import "golang.org/x/crypto/bcrypt"

// EncryptedPassword returns the encrypted hash of the password at the default cost.
func EncryptedPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
func CompareHashAndPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
