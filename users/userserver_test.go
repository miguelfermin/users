package users_test

import (
	"bytes"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/http/httptest"
	"testing"
	"users/database/demo"
	"users/errors"
	"users/models"
	"users/users"
)

func TestRegister(t *testing.T) {
	/* ------------------ Requirements ------------------
	Checks:
		api key
		required fields: firstName, lastName, username, password
		username length >= 6
		password length >= 8
		password contains at least one number
		password contains at least one upper-cased letter
		password != username
		first user ever created becomes system admin
		subsequent users role defaults to guest
	-------------------------------------------------- */
	srv := newServer()

	type request struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}

	tt := []struct {
		name   string
		user   request
		role   models.Role
		id     string
		apiKey string
		err    *errors.Error
	}{
		{
			"Success: first user ever created becomes system admin",
			request{"miguelfermin", "miGuel1234", "Miguel", "Fermin"},
			models.Admin,
			"1",
			srv.Server.ApiKey,
			nil,
		},
		{
			"Success: subsequent users role defaults to guest",
			request{"peterjones", "miGuel1234", "Miguel", "Fermin"},
			models.Guest,
			"2",
			srv.Server.ApiKey,
			nil,
		},
		{
			"Error: User already exist",
			request{"miguelfermin", "miGuel1234", "Miguel", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.UserAlreadyExist(),
		},
		{
			"Error: Bad APIKey",
			request{"miguelfermin", "miGuel1234", "Miguel", "Fermin"},
			models.Admin,
			"",
			"",
			errors.APIKey(),
		},
		{
			"Error: required fields, username",
			request{"", "miGuel1234", "Miguel", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.MissingRequiredFields(),
		},
		{
			"Error: required fields, password",
			request{"miguelfermin", "", "Miguel", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.MissingRequiredFields(),
		},
		{
			"Error: required fields, firstName",
			request{"miguelfermin", "miGuel1234", "", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.MissingRequiredFields(),
		},
		{
			"Error: required fields, lastName",
			request{"miguelfermin", "miGuel1234", "Miguel", ""},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.MissingRequiredFields(),
		},
		{
			"Error: username length >= 6",
			request{"migue", "miGuel1234", "Miguel", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.UsernameValidation(),
		},
		{
			"Error: password length >= 8",
			request{"noahfermin", "miguel1", "Miguel", "Fermin"},
			models.Admin,
			"",
			srv.Server.ApiKey,
			errors.PasswordLength(),
		},
		{
			"Error: password != username",
			request{"noahfermin", "noahfermin", "Miguel", "Fermin"},
			models.Admin,
			"1",
			srv.Server.ApiKey,
			errors.PasswordSameAsUsername(),
		},
		{
			"Error: password contains at least one upper-cased letter",
			request{"peterjones", "sohfermin", "Miguel", "Fermin"},
			models.Admin,
			"2",
			srv.Server.ApiKey,
			errors.PasswordMissingCharUpper(),
		},
		{
			"Error: password contains at least one upper-cased letter",
			request{"peterjones", "sohWFermin", "Miguel", "Fermin"},
			models.Admin,
			"2",
			srv.Server.ApiKey,
			errors.PasswordMissingCharNumeric(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			body := getBody(tc.user)
			r := httptest.NewRequest("POST", "/api/users_auth/register", body)
			r.Header.Add("ApiKey", tc.apiKey)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}

			res := mapToGetUserResponse(w)

			if res.Identifier != tc.id {
				t.Errorf("Identifier: expected <%v>, got <%v>", tc.id, res.Identifier)
			}
			if res.FirstName != tc.user.FirstName {
				t.Errorf("FirstName: expected <%v>, got <%v>", tc.user.FirstName, res.FirstName)
			}
			if res.LastName != tc.user.LastName {
				t.Errorf("LastName: expected <%v>, got <%v>", tc.user.LastName, res.LastName)
			}
			if res.Role != tc.role {
				t.Errorf("Role: expected <%v>, got <%v>", tc.role, res.Role)
			}
			if res.IsActive != true {
				t.Errorf("IsActive: expected <%v>, got <%v>", true, res.IsActive)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	/* ------------------ Requirements ------------------
	Checks:
		api key
		user doesn't exists
		credentials are correct
		all input fields (username, password) are required: implicitly handled by other checks
	-------------------------------------------------- */
	srv := newServer()

	// need to register for first login test case
	register("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)

	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	tt := []struct {
		name   string
		user   request
		role   models.Role
		id     string
		apiKey string
		err    *errors.Error
	}{
		{
			name:   "Success",
			user:   request{"miguelfermin", "miGuel1234"},
			role:   models.Admin,
			id:     "1",
			apiKey: srv.Server.ApiKey,
		},
		{
			name: "Error: Bad APIKey",
			user: request{"miguelfermin", "miGuel1234"},
			role: models.Admin,
			err:  errors.APIKey(),
		},
		{
			name:   "Error: user doesn't exists",
			user:   request{"helloworld", "myWorld1234"},
			role:   models.Admin,
			id:     "1",
			apiKey: srv.Server.ApiKey,
			err:    errors.UserNotFound(),
		},
		{
			name:   "Error: credentials are not correct",
			user:   request{"miguelfermin", "miGuel12345"},
			role:   models.Admin,
			id:     "1",
			apiKey: srv.Server.ApiKey,
			err:    errors.CompareHashAndPassword(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			body := getBody(tc.user)
			r := httptest.NewRequest("POST", "/api/users_auth/login", body)
			r.Header.Add("ApiKey", tc.apiKey)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}

			res := mapToLoginResponse(w)

			if res.AccessToken == "" {
				t.Errorf("AccessToken: expected <non-empty>, got <empty string>")
			}
			if res.Issued.IsZero() {
				t.Errorf("Issued: must not be Zero value")
			}
			if res.Expires.IsZero() {
				t.Errorf("Expires: must not be Zero value")
			}
			if res.UserId != tc.id {
				t.Errorf("UserId: expected <%v>, got <%v>", tc.id, res.UserId)
			}
			if res.UserRole != tc.role {
				t.Errorf("UserRole: expected <%v>, got <%v>", tc.role, res.UserRole)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	/* ------------------ Requirements ------------------
	Checks:
		api key
		user exists
	-------------------------------------------------- */
	srv := newServer()

	// need to register and login for logout test case
	username := "miguelfermin"
	password := "miGuel1234"
	register(username, password, "Miguel", "Fermin", srv)
	token := login(username, password, srv)

	tt := []struct {
		name   string
		role   models.Role
		apiKey string
		token  string
		err    *errors.Error
	}{
		{
			name:   "Success",
			role:   models.Admin,
			apiKey: srv.Server.ApiKey,
			token:  token.AccessToken,
		},
		{
			name:   "Error",
			role:   models.Admin,
			apiKey: srv.Server.ApiKey,
			token:  token.AccessToken,
			err:    errors.AccessTokenNotFound(),
		},
		{
			name:  "Error: Bad APIKey",
			role:  models.Admin,
			token: token.AccessToken,
			err:   errors.APIKey(),
		},
		{
			name:   "Error: access token not found",
			role:   models.Admin,
			apiKey: srv.Server.ApiKey,
			err:    errors.AccessTokenNotFound(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("DELETE", "/api/users_auth/logout", nil)
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
		})
	}
}

func TestGetUsers(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access admin
	//		role is admin, member
	// --------------------------------------------------
	srv := newServer()

	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	registerSampleUsers(srv)

	// this username is registered inside the "registerSampleUsers" function
	// new registered user role defaults to "Guest"
	guest := login("michaeljordan", "miGuel1234", srv)

	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		err       *errors.Error
	}{
		{
			name:      "Success",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
		},
		{
			name: "Error: Bad APIKey",
			err:  errors.APIKey(),
		},
		{
			name:   "Error: Bad SecretKey",
			apiKey: srv.Server.ApiKey,
			token:  admin.AccessToken,
			err:    errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Error: Role should be admin or member",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			err:       errors.RoleMemberRequired(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/users", nil)
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}

			res := mapToGetAllUsersResponse(w)
			count := len(res.Users)
			if count != 7 {
				t.Errorf("Users Count: expected <%v>, got <%v>", 7, count)
			}
		})
	}
}

func TestGetUserById(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access token
	//		role guest can only get himself/herself
	// --------------------------------------------------
	srv := newServer()
	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	guest := registerAndLogin("noahfermin", "noAh1234", "Noah", "Fermin", srv)

	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		userId    string
		err       *errors.Error
	}{
		{
			name:      "Success: guest can GET self",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			userId:    "2",
		},
		{
			name:      "Success: admin can GET self",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			userId:    "1",
		},
		{
			name:      "Success: admin can get other users",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			userId:    "2",
		},
		{
			name:   "Error: Bad APIKey",
			userId: "2",
			err:    errors.APIKey(),
		},
		{
			name:   "Error: Bad SecretKey",
			apiKey: srv.Server.ApiKey,
			token:  guest.AccessToken,
			userId: "2",
			err:    errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			userId:    "2",
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Error: Role Guest can not GET other users",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			userId:    "1",
			err:       errors.RoleMemberRequired(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/users/"+tc.userId, nil)
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
		})
	}
}

func TestGetUserByToken(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access token
	//		role is admin, member
	// --------------------------------------------------
	srv := newServer()
	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	guest := registerAndLogin("noahfermin", "noAh1234", "Noah", "Fermin", srv)

	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		err       *errors.Error
	}{
		{
			name:      "Error: Bad APIKey",
			apiKey:    "hi_there",
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			err:       errors.APIKey(),
		},
		{
			name:   "Error: Bad SecretKey",
			apiKey: srv.Server.ApiKey,
			token:  admin.AccessToken,
			err:    errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Success: admin can GET self by token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
		},
		{
			name:      "Error: guest can not GET self by token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			err:       errors.RoleMemberRequired(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/users_token", nil)
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Bad Status Code, expecting error (%v) for tc %v", tc.err, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Expecting Error for tc %v", tc.name)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access token
	//		role is admin, member
	//		required fields: firstName, lastName, username, password
	//		username length >= 6
	//		password length >= 8
	//		password contains at least one number
	//		password contains at least one upper-cased letter
	//		password != username
	//		first even user defaults to role "admin"
	//		subsequent users defaults to role "guest"
	//		IsActive field defaults to true
	// --------------------------------------------------
	srv := newServer()
	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	guest := registerAndLogin("noahfermin", "noAh1234", "Noah", "Fermin", srv)

	if admin.UserRole != models.Admin {
		t.Errorf("First ever user role must be Admin, but got <%v>", admin.UserRole)
	}
	if guest.UserRole != models.Guest {
		t.Errorf("subsequent users role must be Guest, but got <%v> for second user", guest.UserRole)
	}

	type request struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}

	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		user      *request
		err       *errors.Error
	}{
		{
			name:      "Success: subsequent users role defaults to guest",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"peterjones", "miGuel1234", "Miguel", "Fermin"},
		},
		{
			name:      "Error: a guest is not allowed to make this request",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			user:      &request{"peterjones2", "miGuel1234", "Miguel", "Fermin"},
			err:       errors.RoleMemberRequired(),
		},
		{
			name:      "Error: Bad APIKey",
			apiKey:    "hi_there",
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			err:       errors.APIKey(),
		},
		{
			name:      "Error: Bad SecretKey",
			apiKey:    srv.Server.ApiKey,
			secretKey: "hi_there",
			token:     admin.AccessToken,
			err:       errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Error: Bad request body",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			err:       errors.IncorrectRequestBody(),
		},
		{
			name:      "Error: required fields, username",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"", "miGuel1234", "Miguel", "Fermin"},
			err:       errors.MissingRequiredFields(),
		},
		{
			name:      "Error: required fields, password",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"miguelfermin", "", "Miguel", "Fermin"},
			err:       errors.MissingRequiredFields(),
		},
		{
			name:      "Error: required fields, firstName",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"miguelfermin", "miGuel1234", "", "Fermin"},
			err:       errors.MissingRequiredFields(),
		},
		{
			name:      "Error: required fields, lastName",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"miguelfermin", "miGuel1234", "Miguel", ""},
			err:       errors.MissingRequiredFields(),
		},
		{
			name:      "Error: username length >= 6",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"migue", "miGuel1234", "Miguel", "Fermin"},
			err:       errors.UsernameValidation(),
		},
		{
			name:      "Error: password length >= 8",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"noahfermin", "miguel1", "Miguel", "Fermin"},
			err:       errors.PasswordLength(),
		},
		{
			name:      "Error: password != username",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"noahfermin", "noahfermin", "Miguel", "Fermin"},
			err:       errors.PasswordSameAsUsername(),
		},
		{
			name:      "Error: password contains at least one upper-cased letter",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"peterjones", "sohfermin", "Miguel", "Fermin"},
			err:       errors.PasswordMissingCharUpper(),
		},
		{
			name:      "Error: password contains at least one upper-cased letter",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"peterjones", "sohWFermin", "Miguel", "Fermin"},
			err:       errors.PasswordMissingCharNumeric(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/users", nil)
			if tc.user != nil {
				r = httptest.NewRequest("POST", "/api/users", getBody(tc.user))
			}
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Incorrect Status Code | Expecting error (%v) | Test case %v", tc.err.Message, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Test Case %v(tc.err = %v) | Status code %v | err %v", tc.name, tc.err, w.Code, err)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
			res := mapToGetUserResponse(w)
			if res.FirstName != tc.user.FirstName {
				t.Errorf("FirstName: expected <%v>, got <%v>", tc.user.FirstName, res.FirstName)
			}
			if res.LastName != tc.user.LastName {
				t.Errorf("LastName: expected <%v>, got <%v>", tc.user.LastName, res.LastName)
			}
			if res.IsActive != true {
				t.Errorf("IsActive: expected <%v>, got <%v>", true, res.IsActive)
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access token
	//		role is admin
	//		password
	//		firstname
	//		lastname
	//		role (except for self)
	//		isActive (except for self)
	//
	//	Required:
	//		Identifier
	//
	//	Optional:
	//		Password
	//		FirstName
	//		LastName
	//		Role
	//		IsActive
	//--------------------------------------------------
	srv := newServer()
	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	guest := registerAndLogin("noahfermin", "noAh1234", "Noah", "Fermin", srv)
	member := registeredAndLoggedInMember(admin, srv)

	type request struct {
		Identifier string      `json:"id"`
		Password   string      `json:"password"`
		FirstName  string      `json:"firstName"`
		LastName   string      `json:"lastName"`
		Role       models.Role `json:"role"`
		IsActive   bool        `json:"isActive"`
	}
	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		user      *request
		err       *errors.Error
	}{
		{
			name:      "Error: Bad APIKey",
			apiKey:    "hi_there",
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			err:       errors.APIKey(),
		},
		{
			name:      "Error: Bad SecretKey",
			apiKey:    srv.Server.ApiKey,
			secretKey: "hi_there",
			token:     admin.AccessToken,
			err:       errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Error: Bad request body",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			err:       errors.IncorrectRequestBody(),
		},
		{
			name:      "Error: required fields, identifier",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{"", "miGuel1234", "Miguel", "Fermin", models.Guest, false},
			err:       errors.MissingRequiredFields(),
		},
		{
			name:      "Error: password length >= 8",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{guest.UserId, "miguel1", "Miguel", "Fermin", models.Guest, false},
			err:       errors.PasswordLength(),
		},
		{
			name:      "Error: password contains at least one upper-cased letter",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{guest.UserId, "sohfermin", "Miguel", "Fermin", models.Guest, false},
			err:       errors.PasswordMissingCharUpper(),
		},
		{
			name:      "Error: password contains at least one upper-cased letter",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{guest.UserId, "sohWFermin", "Miguel", "Fermin", models.Guest, false},
			err:       errors.PasswordMissingCharNumeric(),
		},
		{
			name:      "Error: a guest is not allowed to make this request",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			user:      &request{"1", "miGuel1234", "Miguel", "Fermin", models.Guest, false},
			err:       errors.RoleAdminRequired(),
		},
		{
			name:      "Error: a member is not allowed to make this request",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     member.AccessToken,
			user:      &request{guest.UserId, "miGuel1234", "Miguel", "Fermin", models.Guest, false},
			err:       errors.RoleAdminRequired(),
		},
		{
			name:      "Error: admin cannot update own Role",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{admin.UserId, "miGuel12345", "Miguel", "Fermin", models.Guest, false},
			err:       errors.RoleUpdateProhibited(),
		},
		{
			name:      "Error: admin cannot update own isAdmin value",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{admin.UserId, "miGuel12345", "Miguel", "Fermin", models.Admin, false},
			err:       errors.DeactivateSelfNotAllowed(),
		},
		{
			name:      "Success: guest user updated",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			user:      &request{guest.UserId, "Peter1234", "Peter", "Jones", models.Member, true},
			err:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("PUT", "/api/users", nil)
			if tc.user != nil {
				r = httptest.NewRequest("PUT", "/api/users", getBody(tc.user))
			}
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Incorrect Status Code | Expecting error (%v) | Test case %v", tc.err.Message, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Test Case %v(tc.err = %v) | Status code %v | err %v", tc.name, tc.err, w.Code, err)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
			res := mapToGetUserResponse(w)
			if res.FirstName != tc.user.FirstName {
				t.Errorf("FirstName: expected <%v>, got <%v>", tc.user.FirstName, res.FirstName)
			}
			if res.LastName != tc.user.LastName {
				t.Errorf("LastName: expected <%v>, got <%v>", tc.user.LastName, res.LastName)
			}
			if res.IsActive != tc.user.IsActive {
				t.Errorf("IsActive: expected <%v>, got <%v>", tc.user.IsActive, res.IsActive)
			}
			if res.Role != tc.user.Role {
				t.Errorf("Role: expected <%v>, got <%v>", tc.user.Role, res.Role)
			}
		})
	}
}

func TestDeleteUser(t *testing.T) {
	// ------------------ Requirements ------------------
	//	Checks:
	//		api key, secret key, access token
	//		role is admin
	//		user cannot delete self
	// --------------------------------------------------
	srv := newServer()
	admin := registerAndLogin("miguelfermin", "miGuel1234", "Miguel", "Fermin", srv)
	guest := registerAndLogin("noahfermin", "noAh1234", "Noah", "Fermin", srv)
	member := registeredAndLoggedInMember(admin, srv)

	if member.UserRole != models.Member {
		t.Errorf("Failed to update guest to member")
	}

	tt := []struct {
		name      string
		apiKey    string
		secretKey string
		token     string
		userId    string
		err       *errors.Error
	}{
		{
			name:      "Error: Bad APIKey",
			apiKey:    "hi_there",
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			userId:    guest.UserId,
			err:       errors.APIKey(),
		},
		{
			name:      "Error: Bad SecretKey",
			apiKey:    srv.Server.ApiKey,
			secretKey: "hi_there",
			token:     admin.AccessToken,
			userId:    guest.UserId,
			err:       errors.SecretKey(),
		},
		{
			name:      "Error: Bad Access Token",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     "hi_there",
			userId:    guest.UserId,
			err:       errors.AccessTokenNotFound(),
		},
		{
			name:      "Error: a Guest is not allowed to make this request",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     guest.AccessToken,
			userId:    guest.UserId,
			err:       errors.RoleAdminRequired(),
		},
		{
			name:      "Error: a Member is not allowed to make this request",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     member.AccessToken,
			userId:    guest.UserId,
			err:       errors.RoleAdminRequired(),
		},
		{
			name:      "Error: you cannot delete yourself",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			userId:    admin.UserId,
			err:       errors.DeleteSelfForbidden(),
		},
		{
			name:      "Success: guest user deleted",
			apiKey:    srv.Server.ApiKey,
			secretKey: srv.Server.SecretKey,
			token:     admin.AccessToken,
			userId:    guest.UserId,
			err:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("DELETE", "/api/users/"+tc.userId, nil)
			r.Header.Add("ApiKey", tc.apiKey)
			r.Header.Add("SecretKey", tc.secretKey)
			r.Header.Add("Authorization", "token "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.err != nil && w.Code == http.StatusOK {
				t.Fatalf("Incorrect Status Code | Expecting error (%v) | Test case %v", tc.err.Message, tc.name)
				return
			}
			if w.Code != http.StatusOK {
				err := mapToError(w)
				if err == nil || tc.err == nil {
					t.Fatalf("Test Case %v(tc.err = %v) | Status code %v | err %v", tc.name, tc.err, w.Code, err)
				}
				if !tc.err.IsEqual(*err) {
					t.Errorf("Error: expected <%v>, got <%v>", tc.err, err)
				}
				return
			}
		})
	}
}

// region Helpers
func newServer() *users.UserServer {
	server := users.Server{
		ApiKey:    "49D56F83-E530-4167-81B1-448FC6EEEEDF",
		SecretKey: "FA17578D-C178-4229-BBB6-6690DB3DF859",
		Router:    httprouter.New(),
		Database:  &demo.UsersDB{},
	}
	userServer := users.NewUserServer(server)
	userServer.Routes()
	return &userServer
}

func register(username, password, firstName, lastName string, srv *users.UserServer) {
	body := getBody(struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}{
		username, password, firstName, lastName,
	})
	r := httptest.NewRequest("POST", "/api/users_auth/register", body)
	r.Header.Add("ApiKey", srv.Server.ApiKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
}

func login(username, password string, srv *users.UserServer) users.LoginResponse {
	body := getBody(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		username, password,
	})
	r := httptest.NewRequest("POST", "/api/users_auth/login", body)
	r.Header.Add("ApiKey", srv.Server.ApiKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	res := mapToLoginResponse(w)
	return *res
}

func registerAndLogin(username, password, firstName, lastName string, srv *users.UserServer) users.LoginResponse {
	register(username, password, firstName, lastName, srv)
	return login(username, password, srv)
}

func registeredAndLoggedInMember(admin users.LoginResponse, srv *users.UserServer) users.LoginResponse {
	firstname := "Peter"
	lastname := "Jones"
	username := "peterjones"
	password := "peTerJo1234"
	member := registerAndLogin(username, password, firstname, lastname, srv)

	body := getBody(struct {
		Identifier string      `json:"id"`
		Password   string      `json:"password"`
		FirstName  string      `json:"firstName"`
		LastName   string      `json:"lastName"`
		Role       models.Role `json:"role"`
		IsActive   bool        `json:"isActive"`
	}{
		Identifier: member.UserId,
		Password:   password,
		FirstName:  firstname,
		LastName:   lastname,
		Role:       models.Member,
	})

	r := httptest.NewRequest("PUT", "/api/users", body)
	r.Header.Add("ApiKey", srv.Server.ApiKey)
	r.Header.Add("SecretKey", srv.Server.SecretKey)
	r.Header.Add("Authorization", "token "+admin.AccessToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	res := mapToGetUserResponse(w)
	member.UserRole = res.Role
	return member
}

func registerSampleUsers(srv *users.UserServer) {
	register("michaeljordan", "miGuel1234", "Michael", "Jordan", srv)
	register("anaconcepcion", "miGuel1235", "Ana", "Concepcion", srv)
	register("noahfermin", "miGuel1236", "Noah", "Fermin", srv)
	register("miladyperez", "miGuel1237", "Milady", "Perez", srv)
	register("peterjones", "miGuel1238", "Peter", "Jones", srv)
	register("mariadecker", "miGuel1239", "Maria", "Decker", srv)
}

func getBody(model interface{}) *bytes.Buffer {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(model)
	if err != nil {
		panic("come on now, could not encode json body")
	}
	return &buf
}

func mapToLoginResponse(w *httptest.ResponseRecorder) *users.LoginResponse {
	var res *users.LoginResponse
	decoder := json.NewDecoder(w.Body)
	decoder.Decode(&res)
	return res
}

func mapToGetUserResponse(w *httptest.ResponseRecorder) *users.UserResponse {
	var res *users.UserResponse
	decoder := json.NewDecoder(w.Body)
	decoder.Decode(&res)
	return res
}

func mapToGetAllUsersResponse(w *httptest.ResponseRecorder) users.GetUsersResponse {
	var res users.GetUsersResponse
	decoder := json.NewDecoder(w.Body)
	_ = decoder.Decode(&res)
	return res
}

func mapToError(w *httptest.ResponseRecorder) *errors.Error {
	var res errors.Error
	decoder := json.NewDecoder(w.Body)
	decoder.Decode(&res)
	return &res
}

//endregion
