package users

import (
	"encoding/json"
	"fmt"
	"net/http"
	"users/errors"
	"users/models"
)

//region Helpers

func onSuccessMsg(w http.ResponseWriter, msg string) {
	onSuccess(w, struct {
		Message string `json:"message"`
	}{Message: msg})
}

func onSuccess(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
}

func onError(err *errors.Error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	_, _ = fmt.Fprintln(w, err.JSON())
}

//endregion

//region Model Mapping

func mapToGetUserResponse(user *models.User) UserResponse {
	return UserResponse{
		Identifier: user.Identifier,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Role:       user.Role,
		IsActive:   user.IsActive,
	}
}

func mapToGetUsersResponse(users []models.User) GetUsersResponse {
	var response = GetUsersResponse{}
	for _, user := range users {
		response.Users = append(response.Users, mapToGetUserResponse(&user))
	}
	return response
}

func mapToLoginRequest(r *http.Request) (*LoginRequest, *errors.Error) {
	var credentials LoginRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&credentials)
	if err != nil {
		return nil, errors.IncorrectRequestBody()
	}
	return &credentials, nil
}

func mapToCreateUserRequest(r *http.Request) (*CreateUserRequest, *errors.Error) {
	var request CreateUserRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		return nil, errors.IncorrectRequestBody()
	}
	return &request, nil
}

func mapToUpdateUserRequest(r *http.Request) (*UpdateUserRequest, *errors.Error) {
	var request UpdateUserRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		return nil, errors.IncorrectRequestBody()
	}
	return &request, nil
}

//endregion
