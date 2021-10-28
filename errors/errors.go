package errors

import (
	"net/http"
)

func APIKey() *Error {
	return &Error{
		Code:       10000,
		StatusCode: http.StatusForbidden,
		Message:    "API Key",
	}
}

func SecretKey() *Error {
	return &Error{
		Code:       10001,
		StatusCode: http.StatusForbidden,
		Message:    "Secret Key",
	}
}

func AccessTokenNotFound() *Error {
	return &Error{
		Code:       10002,
		StatusCode: http.StatusUnauthorized,
		Message:    "Access Token not found",
	}
}

func AccessTokenExpired() *Error {
	return &Error{
		Code:       10003,
		StatusCode: http.StatusUnauthorized,
		Message:    "Access Token expired",
	}
}

func AccessTokenMalformed() *Error {
	return &Error{
		Code:       10004,
		StatusCode: http.StatusBadRequest,
		Message:    "Access Token malformed",
	}
}

func UserAlreadyExist() *Error {
	return &Error{
		Code:       10005,
		StatusCode: http.StatusBadRequest,
		Message:    "User already exist",
	}
}

func MissingRequiredFields() *Error {
	return &Error{
		Code:       10006,
		StatusCode: http.StatusBadRequest,
		Message:    "Missing required field(s). Refer to documentation",
	}
}

func UsernameValidation() *Error {
	return &Error{
		Code:       10007,
		StatusCode: http.StatusBadRequest,
		Message:    "username character length must be at least 6",
	}
}

func PasswordLength() *Error {
	return &Error{
		Code:       10008,
		StatusCode: http.StatusBadRequest,
		Message:    "password failed length requirement. Refer to documentation",
	}
}

func PasswordSameAsUsername() *Error {
	return &Error{
		Code:       10009,
		StatusCode: http.StatusBadRequest,
		Message:    "password and username must not be the same",
	}
}

func PasswordMissingCharUpper() *Error {
	return &Error{
		Code:       10010,
		StatusCode: http.StatusBadRequest,
		Message:    "password requires at least one upper case character",
	}
}

func PasswordMissingCharNumeric() *Error {
	return &Error{
		Code:       10011,
		StatusCode: http.StatusBadRequest,
		Message:    "password requires at least one numeric character",
	}
}

func IncorrectRequestBody() *Error {
	return &Error{
		Code:       10012,
		StatusCode: http.StatusBadRequest,
		Message:    "Incorrect data type in request body. Refer to documentation",
	}
}

func InternalServer(message string) *Error {
	return &Error{
		Code:       10013,
		StatusCode: http.StatusInternalServerError,
		Message:    message,
	}
}

func UserNotFound() *Error {
	return &Error{
		Code:       10014,
		StatusCode: http.StatusNotFound,
		Message:    "User not found",
	}
}

func CompareHashAndPassword() *Error {
	return &Error{
		Code:       10015,
		StatusCode: http.StatusNotFound,
		Message:    "User not found",
	}
}

func RoleMemberRequired() *Error {
	return &Error{
		Code:       10016,
		StatusCode: http.StatusForbidden,
		Message:    "Your role does not permit access to this API call",
	}
}

func RoleAdminRequired() *Error {
	return &Error{
		Code:       10017,
		StatusCode: http.StatusForbidden,
		Message:    "Your role does not permit access to this API call",
	}
}

func UnknownRole() *Error {
	return &Error{
		Code:       10017,
		StatusCode: http.StatusBadRequest,
		Message:    "Unknown Role. Please refer to documentation.",
	}
}

func RoleUpdateProhibited() *Error {
	return &Error{
		Code:       10018,
		StatusCode: http.StatusForbidden,
		Message:    "Role update prohibited. You cannot change your own Role",
	}
}

func DeactivateSelfNotAllowed() *Error {
	return &Error{
		Code:       10019,
		StatusCode: http.StatusForbidden,
		Message:    "You cannot deactivate your own account. This must be done by another admin.",
	}
}

func DeleteSelfForbidden() *Error {
	return &Error{
		Code:       10020,
		StatusCode: http.StatusForbidden,
		Message:    "You cannot delete yourself",
	}
}
