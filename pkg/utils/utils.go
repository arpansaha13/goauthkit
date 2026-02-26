package utils

import (
	utils_internal "github.com/arpansaha13/goauthkit/internal/utils"
)

type PasswordHasher = utils_internal.PasswordHasher
type Validator = utils_internal.Validator

func NewPasswordHasher() *PasswordHasher {
	return utils_internal.NewPasswordHasher()
}

func NewValidator() *Validator {
	return utils_internal.NewValidator()
}

func GenerateOTP(length int) (string, error) {
	return utils_internal.GenerateOTP(length)
}

// func HashOTPCode(code string) (string, error) {
// 	return utils_internal.HashOTPCode(code)
// }

// func VerifyOTPCode(hash, code string) bool {
// 	return utils_internal.VerifyOTPCode(hash, code)
// }
