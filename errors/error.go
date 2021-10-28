package errors

import (
	"encoding/json"
	"fmt"
)

// Error represents a request error.
type Error struct {
	// A System specific error code. See "Error Codes" table for more information.
	Code int `json:"code"`
	// The HTTP Status Code.
	StatusCode int `json:"statusCode"`
	// A localized user-facing error message.
	Message string `json:"message"`
	// An object containing information about the error. (Optional)
	Info interface{} `json:"info"`
}

func (e *Error) Error() string {
	return e.JSON()
}

// IsEqual compares itself with other error. This method compares all fields except Info.
func (e *Error) IsEqual(other Error) bool {
	return e.Code == other.Code && e.StatusCode == other.StatusCode && e.Message == other.Message
}

// JSON returns a json representation of the error.
func (e *Error) JSON() string {
	mJson, err := json.Marshal(e)
	if err != nil {
		s := "{\"code\": \"%v\", \"statusCode\": \"%v\", \"message\": \"%v\"}"
		return fmt.Sprintf(s, e.Code, e.StatusCode, e.Message)
	}
	return string(mJson)
}
