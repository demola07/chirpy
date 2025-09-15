# Chirpy

A Twitter-like social media API built with Go and PostgreSQL. Chirpy allows users to create accounts, post short messages (chirps), and interact with content from other users.

## Features

### User Management
- **User Registration**: Create new user accounts with email and password
- **Authentication**: Secure login with JWT tokens and refresh token support
- **User Updates**: Update email and password for existing accounts
- **Premium Upgrades**: Support for upgrading users to "Chirpy Red" premium status via webhooks

### Chirp Management
- **Create Chirps**: Post messages up to 140 characters
- **View Chirps**: Fetch all chirps or filter by specific author
- **Sorting**: Sort chirps by creation date (ascending or descending)
- **Delete Chirps**: Users can delete their own chirps
- **Individual Chirp Access**: Retrieve specific chirps by ID

### Security & Authentication
- **JWT Authentication**: Secure API endpoints with JSON Web Tokens
- **Refresh Tokens**: Long-lived tokens for seamless re-authentication
- **Password Hashing**: Secure password storage using bcrypt
- **Token Revocation**: Ability to revoke refresh tokens
- **API Key Authentication**: Webhook endpoints protected with API keys

### Admin Features
- **Metrics Dashboard**: Track application usage and visitor counts
- **Reset Functionality**: Development-only endpoint to reset all data
- **Health Check**: API health monitoring endpoint

## Tech Stack

- **Backend**: Go (Golang)
- **Database**: PostgreSQL
- **Authentication**: JWT tokens with bcrypt password hashing
- **Database Migrations**: Goose for schema management
- **Code Generation**: SQLC for type-safe database queries
- **Environment Management**: godotenv for configuration

## API Endpoints

### Public Endpoints
- `GET /api/healthz` - Health check
- `POST /api/users` - Create user account
- `POST /api/login` - User login
- `GET /api/chirps` - Get all chirps (supports `?author_id=<uuid>` and `?sort=asc|desc`)
- `GET /api/chirps/{chirpID}` - Get specific chirp

### Authenticated Endpoints
- `POST /api/chirps` - Create new chirp
- `PUT /api/users` - Update user information
- `DELETE /api/chirps/{chirpID}` - Delete own chirp
- `POST /api/refresh` - Refresh access token
- `POST /api/revoke` - Revoke refresh token

### Admin Endpoints
- `GET /admin/metrics` - View usage metrics
- `POST /admin/reset` - Reset all data (dev only)

### Webhook Endpoints
- `POST /api/polka/webhooks` - Handle user upgrade events

## Getting Started

### Prerequisites
- Go 1.24.3 or later
- PostgreSQL database
- Environment variables configured

### Environment Variables
Create a `.env` file with:
```env
DB_URL=postgres://username:password@localhost/chirpy?sslmode=disable
JWT_SECRET=your-jwt-secret-key
PLATFORM=dev
POLKA_KEY=your-polka-api-key
```

### Database Setup
1. Create a PostgreSQL database
2. Run migrations using Goose:
   ```bash
   goose postgres $DB_URL up
   ```

### Building and Running

To build the application:
```bash
go build -o chirpy && ./chirpy
```

To run directly:
```bash
go run .
```

The server will start on `http://localhost:8080`

### Development
- The application includes a simple web interface at `/app/`
- Static assets are served from `/assets/`
- Admin metrics are available at `/admin/metrics`

## Project Structure

```
chirpy/
├── assets/                 # Static assets (images, etc.)
├── internal/
│   ├── auth/              # Authentication utilities
│   └── database/          # Database models and queries
├── sql/
│   ├── queries/           # SQL query definitions
│   └── schema/            # Database migration files
├── main.go                # Main application entry point
├── index.html             # Simple web interface
└── README.md              # This file
```

## Contributing

This is a learning project demonstrating modern Go web development practices including:
- RESTful API design
- Database integration with SQLC
- JWT authentication
- Middleware patterns
- Error handling
- Environment-based configuration
