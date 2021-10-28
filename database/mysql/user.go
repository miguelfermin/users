package mysql

import (
	"database/sql"
	"github.com/google/uuid"
	"strconv"
	"time"
	"users/database"
	"users/errors"
	"users/models"
)

// NewUsersDB initializes a new database.User.
func NewUsersDB(db *sql.DB) database.User {
	repo := usersDB{db: db}
	return &repo
}

type usersDB struct {
	db *sql.DB
}

func (u usersDB) CreateUser(user models.User) (*models.User, *errors.Error) {
	// TODO: User has new fields, need to update query statement
	stmt, err := u.db.Prepare("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	res, err := stmt.Exec(user.Username, user.Password, user.FirstName, user.LastName, user.Role, nil)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	uid := strconv.FormatInt(lastID, 10)
	user.Identifier = uid

	return &user, nil
}

func (u usersDB) CreateToken(user models.User) (*models.Token, *errors.Error) {
	stmt, err := u.db.Prepare("INSERT INTO tokens VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	uuid := uuid.New().String()
	issued := time.Now()
	expires := issued.Add(time.Hour * 24)

	res, err := stmt.Exec(uuid, user.Identifier, issued, expires, user.Role)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	_, err2 := res.LastInsertId()
	if err2 != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	token := models.Token{
		ID:       uuid,
		Issued:   issued,
		Expires:  expires,
		UserRole: user.Role,
		UserID:   user.Identifier,
	}
	return &token, nil
}

func (u usersDB) CountUsers() (int, *errors.Error) {
	stmt, err := u.db.Prepare("SELECT COUNT(*) as count FROM users")
	if err != nil {
		return -1, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var count int
	err = stmt.QueryRow().Scan(&count)
	if err != nil {
		msg := "Failed to get users count. SQL Error: " + err.Error()
		return -1, &errors.Error{StatusCode: 500, Message: msg}
	}

	return count, nil
}

func (u usersDB) ReadUsers() ([]models.User, *errors.Error) {
	// TODO: User has new fields, need to update query statement
	stmt, err := u.db.Prepare("SELECT * FROM users")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var username string
	var password string
	var firstName string
	var lastName string
	var role int
	var id string

	users := []models.User{}

	rows, err := stmt.Query()
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer rows.Close()

	for rows.Next() {
		rowErr := rows.Scan(&username, &password, &firstName, &lastName, &role, &id)
		if rowErr != nil {
			return nil, &errors.Error{StatusCode: 500, Message: rowErr.Error()}
		}

		users = append(users, models.User{
			Username:   username,
			Password:   password,
			Identifier: id,
			FirstName:  firstName,
			LastName:   lastName,
			Role:       models.Role(role),
		})
	}

	if err = rows.Err(); err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	return users, nil
}

func (u usersDB) ReadUserByID(id string) (*models.User, *errors.Error) {
	// TODO: User has new fields, need to update query statement
	stmt, err := u.db.Prepare("SELECT * FROM users WHERE id = ?")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var username string
	var password string
	var firstname string
	var lastname string
	var role int
	var identifier string

	var user *models.User

	rows, err := stmt.Query(id)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer rows.Close()

	for rows.Next() {
		rowErr := rows.Scan(&username, &password, &firstname, &lastname, &role, &identifier)
		if rowErr != nil {
			return nil, &errors.Error{StatusCode: 500, Message: rowErr.Error()}
		}

		user = &models.User{
			Username:   username,
			Password:   password,
			Identifier: identifier,
			FirstName:  firstname,
			LastName:   lastname,
			Role:       models.Role(role),
		}
	}

	if err = rows.Err(); err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if user == nil {
		return nil, &errors.Error{StatusCode: 404, Message: "Not Found: User"}
	}

	return user, nil
}

// TODO: figure out why the return value is an slice of users.
func (u usersDB) ReadUserByUsername(username string) (*models.User, *errors.Error) {
	stmt, err := u.db.Prepare("SELECT * FROM users WHERE username = ?")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var scannedUsername string // once working, check if this is even needed
	var password string
	var firstname string
	var lastname string
	var role int
	var identifier string

	users := []models.User{}

	rows, err := stmt.Query(username)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer rows.Close()

	for rows.Next() {
		rowErr := rows.Scan(&scannedUsername, &password, &firstname, &lastname, &role, &identifier)
		if rowErr != nil {
			return nil, &errors.Error{StatusCode: 500, Message: rowErr.Error()}
		}

		users = append(users, models.User{
			Username:   scannedUsername,
			Password:   password,
			Identifier: identifier,
			FirstName:  firstname,
			LastName:   lastname,
			Role:       models.Role(role),
		})
	}

	if err = rows.Err(); err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if len(users) == 0 {
		return nil, &errors.Error{StatusCode: 404, Message: "User Not Found"}
	}

	return &users[0], nil
}

func (u usersDB) ReadTokenByID(id string) (*models.Token, *errors.Error) {
	stmt, err := u.db.Prepare("SELECT * FROM tokens WHERE id = ?")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var token *models.Token

	var uuid string
	var userID string
	var issued time.Time
	var expires time.Time
	var role models.Role

	rows, err := stmt.Query(id)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer rows.Close()

	for rows.Next() {
		rowErr := rows.Scan(&uuid, &userID, &issued, &expires, &role)
		if rowErr != nil {
			return nil, &errors.Error{StatusCode: 500, Message: rowErr.Error()}
		}

		token = &models.Token{
			ID:       uuid,
			Issued:   issued,
			Expires:  expires,
			UserRole: role,
			UserID:   userID,
		}
	}

	if err = rows.Err(); err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if token == nil {
		return nil, &errors.Error{StatusCode: 404, Message: "Not Found: Token to fetch"}
	}

	return token, nil
}

func (u usersDB) ReadTokens() ([]models.Token, *errors.Error) {
	stmt, err := u.db.Prepare("SELECT * FROM tokens")
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer stmt.Close()

	var uuid string
	var userID string
	var issued time.Time
	var expires time.Time
	var role models.Role

	tokens := []models.Token{}

	rows, err := stmt.Query()
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	defer rows.Close()

	for rows.Next() {
		rowErr := rows.Scan(&uuid, &userID, &issued, &expires, &role)
		if rowErr != nil {
			return nil, &errors.Error{StatusCode: 500, Message: rowErr.Error()}
		}
		tokens = append(tokens, models.Token{
			ID:       uuid,
			Issued:   issued,
			Expires:  expires,
			UserRole: role,
			UserID:   userID,
		})
	}

	if err = rows.Err(); err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if tokens == nil {
		return nil, &errors.Error{StatusCode: 404, Message: "Not Found: Token to fetch"}
	}

	return tokens, nil
}

func (u usersDB) UpdateUser(user models.User) (*models.User, *errors.Error) {
	// TODO: User has new fields, need to update query statement
	rows, err := u.db.Query("SELECT * FROM users WHERE id = ?", user.Identifier)
	if err != nil {
		return nil, &errors.Error{StatusCode: 404, Message: err.Error()}
	}
	if rows.Next() == false {
		return nil, &errors.Error{StatusCode: 404, Message: "Not Found"}
	}

	str := "UPDATE users SET username=?, password=?, firstname=?, lastname=?, role=? WHERE id=?"
	stmt, err := u.db.Prepare(str)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	_, err = stmt.Exec(user.Username, user.Password, user.FirstName, user.LastName, user.Role, user.Identifier)
	if err != nil {
		return nil, &errors.Error{StatusCode: 500, Message: err.Error()}
	}
	return &user, nil
}

func (u usersDB) DeleteUser(id string) *errors.Error {
	stmt, err := u.db.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	res, err := stmt.Exec(id)
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if rowCnt == 0 {
		return &errors.Error{StatusCode: 404, Message: "Not Found"}
	}

	return nil
}

func (u usersDB) DeleteToken(id string) *errors.Error {
	stmt, err := u.db.Prepare("DELETE FROM tokens WHERE id = ?")
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	res, err := stmt.Exec(id)
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if rowCnt == 0 {
		return &errors.Error{StatusCode: 404, Message: "Not Found: Token to delete"}
	}

	return nil
}

func (u usersDB) DeleteTokenByUserID(userID string) *errors.Error {
	stmt, err := u.db.Prepare("DELETE FROM tokens WHERE user_id = ?")
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	res, err := stmt.Exec(userID)
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		return &errors.Error{StatusCode: 500, Message: err.Error()}
	}

	if rowCnt == 0 {
		return &errors.Error{StatusCode: 404, Message: "Not Found: Deleted User Token to delete"}
	}

	return nil
}
