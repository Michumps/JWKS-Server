#JWKS Server

## Description
A JSON Web Key Set (JWKS) server that generates asymmetric RSA key pairs for signing JWTs

## Install

1. Install Dependencies:
```bash 
$npm install
```

2. Start Server:
```bash 
$npm start
```

Server will run on specified *port* (8080 for this project)

## Usage

### POST /auth
Used to generate a signed JWT

**Query Parameters:**
`expired=true`: will generate an expired JWT for testing purposes

**Testing Examples:**
```bash
curl -X POST http://localhost:8080/auth

curl -X POST http://localhost:8080/auth?expired=true
```

# Both examples should return a signed JWT in JSON format

### GET /.well-known/jwks.json

**Testing Example:**
```bash
curl http://localhost:8080/.well-known/jwks.json
```

# Should return key(s) in JSON following proper JWKS format


## Testing
- JWTs can be verified using [jwt.io](https://jwt.io) using the exposed keys from the JWKS endpoint
- Test suite can be executed using npm test

