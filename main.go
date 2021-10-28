package main

import (
	"database/sql"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"os"
	"time"
	"users/database"
	"users/database/demo"
	"users/database/mysql"
	"users/errors"
	"users/models"
	"users/users"
)

func main() {
	//startServer()
	startServerDemo()
}

func startServer() {
	apiKey := os.Getenv("USERS_SERVER_API_KEY")
	secretKey := os.Getenv("USERS_SERVER_SECRET_KEY")
	addr := os.Getenv("USERS_SERVER_TCP_ADDRESS")
	driverName := os.Getenv("USERS_SERVER_SQL_DRIVER_NAME")
	dataSourceName := os.Getenv("USERS_SERVER_SQL_DATA_SOURCE_NAME")

	log.Println("users running on addr: ", addr)
	log.Println("users db driverName:   ", driverName)
	log.Println("users db dataSource:   ", dataSourceName)
	log.Println("users apiKey:          ", apiKey)
	log.Println("users secretKey:       ", secretKey)

	db := setupDatabase(driverName, dataSourceName)
	defer db.Close()

	userDB := mysql.NewUsersDB(db)
	router := httprouter.New()

	server := users.Server{
		ApiKey:    apiKey,
		SecretKey: secretKey,
		Router:    router,
		Database:  userDB,
	}

	userServer := users.NewUserServer(server)
	userServer.Routes()

	t := startCleanupProcess(userDB)
	defer t.Stop()

	log.Fatal(http.ListenAndServe(addr, router))
}

func startServerDemo() {
	userDB := &demo.UsersDB{}
	router := httprouter.New()

	apiKey := "49D56F83-E530-4167-81B1-448FC6EEEEDF"
	secretKey := "FA17578D-C178-4229-BBB6-6690DB3DF859"
	addr := ":8000"

	log.Println("erp-auth-demo addr:   ", addr)
	log.Println("erp-auth-demo ApiKey: ", apiKey)

	server := users.Server{
		ApiKey:    apiKey,
		SecretKey: secretKey,
		Router:    router,
		Database:  userDB,
	}

	userServer := users.NewUserServer(server)
	userServer.Routes()

	log.Fatal(http.ListenAndServe(addr, router))
}

func setupDatabase(driverName, dataSourceName string) *sql.DB {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// TODO: Create an external "cleanup_service" for this type of tasks.
func startCleanupProcess(db database.User) *time.Ticker {
	duration := time.Hour * 12
	ticker := time.NewTicker(duration)
	go func() {
		for range ticker.C {
			_ = revokeExpiredTokens(db)
		}
	}()
	return ticker
}

func revokeExpiredTokens(db database.User) *errors.Error {
	tokens, err := db.ReadTokens()
	if err != nil {
		return &errors.Error{StatusCode: 404, Message: "Not Found: no tokens to revoke"}
	}
	var toDelete []models.Token
	now := time.Now()

	for _, token := range tokens {
		if now.After(token.Expires) {
			if toDelete == nil {
				toDelete = []models.Token{token}
			} else {
				toDelete = append(toDelete, token)
			}
		}
	}
	if toDelete == nil {
		log.Println("Revoker: nothing to revoke.")
		return nil
	}
	for _, t := range toDelete {
		err = db.DeleteToken(t.ID)
	}
	if err != nil {
		log.Println("Failed to delete expired access tokens")
		return err
	}
	log.Printf("Revoker: revoked %v tokens.", len(toDelete))
	return nil
}
