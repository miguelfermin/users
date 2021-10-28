// Package users creates an http users, Router, and API handlers.
package users

import (
	"context"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"strings"
	"time"
	"users/database"
	"users/errors"
	"users/models"
)

type HttpRouterFunc = func(http.ResponseWriter, *http.Request, httprouter.Params)

type authContextKey string

const userIdKey = authContextKey("com.company.userservice.ctx.key.userId")

type Server struct {
	ApiKey    string
	SecretKey string
	Router    *httprouter.Router
	Database  database.User
}

func (s *Server) OpenHandler(fn HttpRouterFunc) HttpRouterFunc {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if r.Header.Get("ApiKey") != s.ApiKey {
			onError(errors.APIKey(), w)
			return
		}
		fn(w, r, ps)
	}
}

func (s *Server) UsersHandler(fn HttpRouterFunc) HttpRouterFunc {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if r.Header.Get("ApiKey") != s.ApiKey {
			onError(errors.APIKey(), w)
			return
		}
		token, err := s.validatedAccessToken(r)
		if err != nil {
			onError(err, w)
			return
		}
		ctx := context.WithValue(r.Context(), userIdKey, token)
		r = r.WithContext(ctx)
		fn(w, r, ps)
	}
}

func (s *Server) SecuredHandler(fn HttpRouterFunc) HttpRouterFunc {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if r.Header.Get("ApiKey") != s.ApiKey {
			onError(errors.APIKey(), w)
			return
		}
		if r.Header.Get("SecretKey") != s.SecretKey {
			onError(errors.SecretKey(), w)
			return
		}
		token, err := s.validatedAccessToken(r)
		if err != nil {
			onError(err, w)
			return
		}
		ctx := context.WithValue(r.Context(), userIdKey, token)
		r = r.WithContext(ctx)
		fn(w, r, ps)
	}
}

func (s *Server) AdminsHandler(fn HttpRouterFunc) HttpRouterFunc {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if r.Header.Get("ApiKey") != s.ApiKey {
			onError(errors.APIKey(), w)
			return
		}
		if r.Header.Get("SecretKey") != s.SecretKey {
			onError(errors.SecretKey(), w)
			return
		}
		token, err := s.validatedAccessToken(r)
		if err != nil {
			onError(err, w)
			return
		}
		if token.UserRole != models.Admin {
			onError(errors.RoleAdminRequired(), w)
			return
		}
		ctx := context.WithValue(r.Context(), userIdKey, token)
		r = r.WithContext(ctx)
		fn(w, r, ps)
	}
}

func (s *Server) validatedAccessToken(r *http.Request) (*models.Token, *errors.Error) {
	tokenID, err := s.validateAuthorizationHeader(r)
	if err != nil {
		return nil, err
	}
	token, err := s.Database.ReadTokenByID(tokenID)
	if err != nil {
		return nil, err
	}
	expired := time.Now().After(token.Expires)
	if expired {
		err := s.Database.DeleteToken(tokenID)
		if err != nil {
			log.Println("Failed to delete expired access token: ", token)
		}
		return nil, errors.AccessTokenExpired()
	}
	return token, nil
}

func (s *Server) validateAuthorizationHeader(r *http.Request) (string, *errors.Error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", errors.AccessTokenMalformed()
	}
	items := strings.Split(authorization, " ")
	if len(items) != 2 {
		return "", errors.AccessTokenMalformed()
	}
	item := strings.ToLower(items[0])
	if item != "token" {
		return "", errors.AccessTokenMalformed()
	}
	return items[1], nil
}
