package users

import (
	"time"
	"users/models"
)

//region Requests

type GetUserRequest struct {
	userId string
}

type DeleteUserRequest struct {
	userId string
}

type UpdateUserRequest struct {
	Identifier string      `json:"id"`
	Username   string      `json:"username"`
	Password   string      `json:"password"`
	FirstName  string      `json:"firstName"`
	LastName   string      `json:"lastName"`
	Role       models.Role `json:"role"`
	IsActive   bool        `json:"isActive"`
}

type CreateUserRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//endregion

//region Responses

type UserResponse struct {
	Identifier string      `json:"id"`
	FirstName  string      `json:"firstName"`
	LastName   string      `json:"lastName"`
	Role       models.Role `json:"role"`
	IsActive   bool        `json:"isActive"`
}

type GetUsersResponse struct {
	Users []UserResponse `json:"users"`
}

type LoginResponse struct {
	AccessToken string      `json:"accessToken"`
	Issued      time.Time   `json:"issued"`
	Expires     time.Time   `json:"expires"`
	UserId      string      `json:"userId"`
	UserRole    models.Role `json:"role"`
}

//endregion
