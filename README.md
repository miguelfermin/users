# Users Service

Single Sign On (SSO) Service for larger systems.

## API

> Version 0.0.0

### Register

**Request:**

```json
{
  "username": "miguelfermin",
  "password": "mySecuredPassWorD123",
  "firstName": "Miguel",
  "lastName": "Fermin"
}
```

**Response:**

```json
{
  "id": "1",
  "firstName": "Miguel",
  "lastName": "Fermin",
  "role": 0,
  "isActive": true
}
```

### Login

**Request:**

```json
{
  "username": "miguelfermin",
  "password": "mySecuredPassWorD123"
}
```

**Response:**

```json
{
  "accessToken": "fa03e0f7-cbcf-44d5-8bd2-a73bd1f664b3",
  "issued": "2021-01-02T02:08:54.176964-05:00",
  "expires": "2021-01-02T03:08:54.176964-05:00",
  "userId": "1",
  "role": 0
}
```

### Logout

**Request:**

```json
{
  "userId": "12345"
}
```

**Response:**

```json
{
  "message": "Logout Success"
}
```

### Get User

**Request:**

```json
{
  "userId": "12345"
}
```

**Response:**

```json
{
  "id": "12345",
  "firstName": "Miguel",
  "lastName": "Fermin",
  "role": 0,
  "isActive": true
}
```

## ...