package users

import (
	"context"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"unicode"
	"users/crypto"
	"users/errors"
	"users/models"
)

type UserServer struct {
	Server Server
}

func NewUserServer(server Server) UserServer {
	return UserServer{
		Server: server,
	}
}

//region API

func (s *UserServer) Routes() {
	router := s.Server.Router
	middleware := s.Server

	router.GET("/api/users", middleware.SecuredHandler(s.handleUserGet))
	router.GET("/api/users/:id", middleware.SecuredHandler(s.handleUserGetById))
	router.GET("/api/users_token", middleware.SecuredHandler(s.handleUserGetByToken))
	router.POST("/api/users", middleware.SecuredHandler(s.handleUserCreate))
	router.PUT("/api/users", middleware.AdminsHandler(s.handleUserUpdate))
	router.DELETE("/api/users/:id", middleware.AdminsHandler(s.handleUserDelete))
	router.POST("/api/users_auth/login", middleware.OpenHandler(s.handleUserLogin))
	router.POST("/api/users_auth/register", middleware.OpenHandler(s.handleUserRegister))
	router.DELETE("/api/users_auth/logout", middleware.UsersHandler(s.handleUserLogout))
}

func (s *UserServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Server.Router.ServeHTTP(w, r)
}

//endregion

//region Handlers

func (s *UserServer) handleUserGet(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if token.UserRole == models.Guest {
		onError(errors.RoleMemberRequired(), w)
		return
	}
	users, err := s.Server.Database.ReadUsers()
	if err != nil {
		onError(err, w)
		return
	}
	response := mapToGetUsersResponse(users)
	if err != nil {
		onError(err, w)
		return
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserGetById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if token.UserRole == models.Guest && token.UserID != id {
		onError(errors.RoleMemberRequired(), w)
		return
	}
	user, err := s.Server.Database.ReadUserByID(id)
	if err != nil {
		onError(err, w)
		return
	}
	response := mapToGetUserResponse(user)
	if err != nil {
		onError(err, w)
		return
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserGetByToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if token.UserRole == models.Guest {
		onError(errors.RoleMemberRequired(), w)
		return
	}
	user, err := s.Server.Database.ReadUserByID(token.UserID)
	if err != nil {
		onError(err, w)
		return
	}
	response := mapToGetUserResponse(user)
	if err != nil {
		onError(err, w)
		return
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserCreate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if token.UserRole == models.Guest {
		onError(errors.RoleMemberRequired(), w)
		return
	}
	response, err := s.registerUser(r)
	if err != nil {
		onError(err, w)
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserUpdate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	updateUserRequest, err := mapToUpdateUserRequest(r)
	if err != nil {
		onError(err, w)
		return
	}
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	// cannot update own role or isActive values
	if token.UserID == updateUserRequest.Identifier {
		if updateUserRequest.Role != token.UserRole {
			onError(errors.RoleUpdateProhibited(), w)
			return
		}
		if updateUserRequest.IsActive == false {
			onError(errors.DeactivateSelfNotAllowed(), w)
			return
		}
	}
	// updateUserRequest's Identifier is not going to be updated, but it's needed for lookup
	if updateUserRequest.Identifier == "" {
		onError(errors.MissingRequiredFields(), w)
		return
	}
	if updateUserRequest.Password != "" {
		if err := s.validateCredentials(updateUserRequest.Username, updateUserRequest.Password); err != nil {
			onError(err, w)
			return
		}
		hashed, err := s.hashPassword(updateUserRequest.Password)
		if err != nil {
			onError(err, w)
			return
		}
		updateUserRequest.Password = *hashed
	}
	if updateUserRequest.Role != models.Admin && updateUserRequest.Role != models.Member && updateUserRequest.Role != models.Guest {
		onError(errors.UnknownRole(), w)
		return
	}

	toUpdate := models.User{
		Identifier: updateUserRequest.Identifier,
		Username:   updateUserRequest.Username,
		Password:   updateUserRequest.Password,
		FirstName:  updateUserRequest.FirstName,
		LastName:   updateUserRequest.LastName,
		Role:       updateUserRequest.Role,
		IsActive:   updateUserRequest.IsActive,
	}

	updated, err := s.Server.Database.UpdateUser(toUpdate)
	if err != nil {
		onError(err, w)
		return
	}

	response := mapToGetUserResponse(updated)
	if err != nil {
		onError(err, w)
		return
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userId := ps.ByName("id")

	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if token.UserID == userId {
		onError(errors.DeleteSelfForbidden(), w)
		return
	}
	err = s.Server.Database.DeleteUser(userId)
	if err != nil {
		onError(err, w)
		return
	}
	err = s.Server.Database.DeleteTokenByUserID(userId)
	if err != nil {
		// no need to fail operation, the token will get expired and cleaned up by another process
		log.Printf("Revoke User (%v) Error -> %v", userId, err.Message)
	}
	onSuccessMsg(w, "Successfully deleted user")
}

func (s *UserServer) handleUserRegister(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	response, err := s.registerUser(r)
	if err != nil {
		onError(err, w)
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	request, err := mapToLoginRequest(r)
	if err != nil {
		onError(err, w)
		return
	}
	user, err := s.Server.Database.ReadUserByUsername(request.Username)
	if err != nil {
		onError(err, w)
		return
	}
	if !crypto.CompareHashAndPassword(user.Password, request.Password) {
		onError(errors.CompareHashAndPassword(), w)
		return
	}
	token, err := s.Server.Database.CreateToken(*user)
	if err != nil {
		onError(err, w)
		return
	}
	response := &LoginResponse{
		AccessToken: token.ID,
		Issued:      token.Issued,
		Expires:     token.Expires,
		UserId:      token.UserID,
		UserRole:    token.UserRole,
	}
	if err != nil {
		onError(err, w)
		return
	}
	onSuccess(w, response)
}

func (s *UserServer) handleUserLogout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token, err := s.extractToken(r.Context())
	if err != nil {
		onError(err, w)
		return
	}
	if err = s.Server.Database.DeleteTokenByUserID(token.UserID); err != nil {
		onError(err, w)
		return
	}
	onSuccessMsg(w, "Logout Success")
}

//endregion

//region Internal
func (s *UserServer) registerUser(r *http.Request) (*UserResponse, *errors.Error) {
	request, err := mapToCreateUserRequest(r)
	if err != nil {
		return nil, err
	}
	// validate request
	if request.Username == "" || request.Password == "" || request.FirstName == "" || request.LastName == "" {
		return nil, errors.MissingRequiredFields()
	}
	if len(request.Username) < 6 {
		return nil, errors.UsernameValidation()
	}
	if err := s.validateCredentials(request.Username, request.Password); err != nil {
		return nil, err
	}

	hashed, err := s.hashPassword(request.Password)
	if err != nil {
		return nil, err
	}
	request.Password = *hashed

	// map to new user
	user := &models.User{
		Username:  request.Username,
		Password:  request.Password,
		FirstName: request.FirstName,
		LastName:  request.LastName,
		IsActive:  true, // default value
	}
	count, err := s.Server.Database.CountUsers()
	if err != nil {
		return nil, errors.InternalServer("Could not validate user role")
	}
	if count == 0 {
		user.Role = models.Admin
	} else {
		user.Role = models.Guest
	}
	created, err := s.Server.Database.CreateUser(*user)
	if err != nil {
		return nil, err
	}
	res := mapToGetUserResponse(created)
	return &res, nil
}

func (s UserServer) extractToken(ctx context.Context) (*models.Token, *errors.Error) {
	token, ok := ctx.Value(userIdKey).(*models.Token)
	if !ok {
		return nil, errors.InternalServer("Failed to retrieve access token from context")
	}
	return token, nil
}

func (s UserServer) validateCredentials(username, password string) *errors.Error {
	if len(password) < 8 {
		return errors.PasswordLength()
	}
	if password == username {
		return errors.PasswordSameAsUsername()
	}
	passwordHasUpperChar := false
	passwordHasNumericChar := false
	for _, r := range password {
		if unicode.IsUpper(r) && unicode.IsLetter(r) {
			passwordHasUpperChar = true
		}
		if unicode.IsNumber(r) {
			passwordHasNumericChar = true
		}
	}
	if !passwordHasUpperChar {
		return errors.PasswordMissingCharUpper()
	}
	if !passwordHasNumericChar {
		return errors.PasswordMissingCharNumeric()
	}
	return nil
}

func (s UserServer) hashPassword(password string) (*string, *errors.Error) {
	hash, herr := crypto.EncryptedPassword(password)
	if herr != nil {
		return nil, errors.InternalServer("Failed to encrypt password")
	}
	return &hash, nil
}

//endregion
