# LockIn - Complete Project Flow Documentation

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Project Architecture](#project-architecture)
4. [Database Schema](#database-schema)
5. [Complete Request Flow](#complete-request-flow)
6. [Security Flow](#security-flow)
7. [API Endpoints](#api-endpoints)
8. [Component Details](#component-details)
9. [Authentication & Authorization Flow](#authentication--authorization-flow)
10. [OAuth2 Google Login Flow](#oauth2-google-login-flow)
11. [Email Service Flow](#email-service-flow)
12. [JWT Token Flow](#jwt-token-flow)

---

## 🎯 Project Overview

**LockIn** is a Spring Boot-based authentication and user management system that provides:
- User registration and login
- JWT-based authentication
- OAuth2 Google login integration
- Email verification via OTP
- Password reset via OTP
- User profile management
- Email notifications

**Base URL**: `http://localhost:8080/api/v1.0`

---

## 🛠 Technology Stack

### Backend Framework
- **Spring Boot 3.5.6** (Java 17)
- **Spring Security** - Authentication & Authorization
- **Spring Data JPA** - Database operations
- **Spring Mail** - Email service
- **Spring OAuth2 Client** - Google OAuth integration

### Database
- **MySQL** - Database server
- **Hibernate** - ORM framework

### Security
- **JWT (JSON Web Tokens)** - Token-based authentication
- **BCrypt** - Password hashing
- **OAuth2** - Third-party authentication

### Libraries
- **Lombok** - Code generation
- **JJWT 0.11.5** - JWT token handling
- **Jakarta Validation** - Input validation

---

## 🏗 Project Architecture

### Package Structure
```
com.Authify.LockIn/
├── Config/              # Security & OAuth2 configuration
├── Controller/          # REST API endpoints
├── Entity/              # JPA entities
├── Exception/           # Global exception handling
├── Filter/              # JWT request filter
├── IO/                  # Request/Response DTOs
├── Repository/          # Data access layer
├── Service/             # Business logic
└── Util/                # Utility classes
```

### Layer Architecture
```
┌─────────────────────────────────────┐
│         Controller Layer             │  ← REST API Endpoints
├─────────────────────────────────────┤
│         Service Layer                │  ← Business Logic
├─────────────────────────────────────┤
│         Repository Layer            │  ← Data Access
├─────────────────────────────────────┤
│         Entity Layer                 │  ← Database Models
└─────────────────────────────────────┘
```

---

## 💾 Database Schema

### UserEntity (tbl_users table)

| Field | Type | Description |
|-------|------|-------------|
| `id` | BIGINT (Primary Key, Auto-increment) | Unique identifier |
| `userID` | VARCHAR (Unique) | UUID-based user identifier |
| `name` | VARCHAR | User's full name |
| `email` | VARCHAR (Unique) | User's email address |
| `password` | VARCHAR | BCrypt hashed password |
| `verifyOtp` | VARCHAR | Email verification OTP |
| `isAccountVerified` | BOOLEAN | Email verification status |
| `verifyOtpExpiredAt` | BIGINT | OTP expiration timestamp (milliseconds) |
| `resetOtp` | VARCHAR | Password reset OTP |
| `resetOtpExpiredAt` | BIGINT | Reset OTP expiration timestamp |
| `createdAt` | TIMESTAMP | Account creation time |
| `updatedAt` | TIMESTAMP | Last update time |

**JPA Configuration**: `spring.jpa.hibernate.ddl-auto=update` (auto-creates/updates schema)

---

## 🔄 Complete Request Flow

### 1. Application Startup Flow

```
1. LockInApplication.main() is called
   ↓
2. Spring Boot auto-configuration loads:
   - Spring Security configuration
   - Database connection (MySQL)
   - JPA/Hibernate setup
   - Email service configuration
   - OAuth2 client configuration
   ↓
3. SecurityConfig.securityFilterChain() configures:
   - CORS settings
   - Public endpoints (login, register, etc.)
   - Protected endpoints (require authentication)
   - JWT filter chain
   - OAuth2 login flow
   ↓
4. Application ready on port 8080
```

### 2. Request Processing Flow

```
HTTP Request
   ↓
[CORS Filter] - Validates origin (localhost:5173)
   ↓
[JWT Request Filter] - Extracts & validates JWT token
   ↓
[Security Filter Chain] - Checks authorization rules
   ↓
[Controller] - Handles business logic
   ↓
[Service Layer] - Processes business operations
   ↓
[Repository Layer] - Database operations
   ↓
[Response] - Returns JSON response
```

---

## 🔐 Security Flow

### Security Configuration (SecurityConfig.java)

**Key Components:**
1. **CORS Configuration**
   - Allowed Origin: `http://localhost:5173`
   - Allowed Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
   - Allowed Headers: All
   - Credentials: Enabled

2. **Public Endpoints** (No authentication required):
   - `/login`
   - `/register`
   - `/send-reset-otp`
   - `/reset-password`
   - `/logout`
   - `/oauth2/**`

3. **Protected Endpoints** (Require JWT authentication):
   - All other endpoints

4. **Session Management**: STATELESS (JWT-based, no server-side sessions)

5. **CSRF**: Disabled (using JWT tokens)

### JWT Request Filter Flow

```
Request arrives
   ↓
Check if path is in PUBLIC_URLS
   ├─ YES → Skip JWT validation, proceed
   └─ NO → Continue
   ↓
Extract JWT from:
   1. Authorization header: "Bearer <token>"
   2. Cookie: "jwt" cookie value
   ↓
If JWT found:
   ├─ Extract email from token
   ├─ Load UserDetails from database
   ├─ Validate token (signature + expiration)
   └─ Set SecurityContext with authentication
   ↓
Proceed to next filter/controller
```

---

## 📡 API Endpoints

### Authentication Endpoints

#### 1. **POST /register**
**Flow:**
```
1. Client sends ProfileRequest (name, email, password)
   ↓
2. ProfileController.register() receives request
   ↓
3. ProfileService.createProfile():
   - Validates email doesn't exist
   - Generates UUID for userID
   - Hashes password with BCrypt
   - Sets isAccountVerified = false
   - Saves to database
   ↓
4. EmailService.sendWelcomeEmail():
   - Sends welcome email via Gmail SMTP
   ↓
5. Returns ProfileResponse with user details
```

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "User registered successfully! Welcome email sent.",
  "data": {
    "userId": "uuid-here",
    "name": "John Doe",
    "email": "john@example.com",
    "isAccountVerified": false
  }
}
```

#### 2. **POST /login**
**Flow:**
```
1. Client sends AuthRequest (email, password)
   ↓
2. AuthController.login() receives request
   ↓
3. AuthenticationManager.authenticate():
   - Loads user from database
   - Validates password with BCrypt
   ↓
4. If authentication successful:
   - Load UserDetails
   - Generate JWT token (10 hours expiration)
   - Create HTTP-only cookie with JWT
   - Return token in response body
   ↓
5. If authentication fails:
   - Return error response
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "data": {
    "email": "john@example.com",
    "token": "jwt-token-here"
  }
}
```

**Cookie Set:**
- Name: `jwt`
- Value: JWT token
- HttpOnly: true
- MaxAge: 1 day
- SameSite: strict

#### 3. **GET /is-authenticated**
**Flow:**
```
1. JWT Filter validates token
   ↓
2. Sets SecurityContext with user email
   ↓
3. Controller extracts email from SecurityContext
   ↓
4. Returns authentication status
```

**Response:**
```json
{
  "message": "Authentication status fetched",
  "data": true/false
}
```

#### 4. **POST /logout**
**Flow:**
```
1. Client sends logout request
   ↓
2. Controller creates empty JWT cookie
   ↓
3. Sets cookie MaxAge to 0 (expires immediately)
   ↓
4. Returns success response
```

**Response:**
```json
{
  "message": "Logged out successfully",
  "data": null
}
```

### Profile Endpoints

#### 5. **GET /profile**
**Flow:**
```
1. JWT Filter validates token
   ↓
2. Extracts email from SecurityContext
   ↓
3. ProfileController.getProfile():
   - Calls ProfileService.getProfile(email)
   - Loads user from database
   - Converts to ProfileResponse
   ↓
4. Returns user profile
```

**Response:**
```json
{
  "message": "Profile fetched successfully!",
  "data": {
    "userId": "uuid-here",
    "name": "John Doe",
    "email": "john@example.com",
    "isAccountVerified": true
  }
}
```

### Email Verification Endpoints

#### 6. **POST /send-otp**
**Flow:**
```
1. JWT Filter validates token
   ↓
2. Extracts email from SecurityContext
   ↓
3. ProfileService.sendOTP():
   - Checks if account already verified
   - Generates 6-digit OTP (100000-999999)
   - Sets expiry: 24 hours from now
   - Saves OTP to database
   ↓
4. EmailService.sendOtpEmail():
   - Sends OTP via email
   ↓
5. Returns success response
```

**Response:**
```json
{
  "message": "Verification OTP sent successfully",
  "data": null
}
```

#### 7. **POST /verify-otp**
**Flow:**
```
1. JWT Filter validates token
   ↓
2. Client sends OTP in request body
   ↓
3. ProfileService.verifyOTP():
   - Loads user from database
   - Validates OTP matches
   - Checks OTP not expired
   - Sets isAccountVerified = true
   - Clears OTP fields
   ↓
4. Returns success response
```

**Request Body:**
```json
{
  "otp": "123456"
}
```

**Response:**
```json
{
  "message": "Email verified successfully",
  "data": null
}
```

### Password Reset Endpoints

#### 8. **POST /send-reset-otp**
**Flow:**
```
1. Client sends email as query parameter
   ↓
2. ProfileService.sendResetOTP():
   - Validates user exists
   - Generates 6-digit OTP
   - Sets expiry: 15 minutes from now
   - Saves OTP to database
   ↓
3. EmailService.sendResetOTPEmail():
   - Sends reset OTP via email
   ↓
4. Returns success response
```

**Request:** `POST /send-reset-otp?email=john@example.com`

**Response:**
```json
{
  "message": "Reset OTP sent to john@example.com",
  "data": null
}
```

#### 9. **POST /reset-password**
**Flow:**
```
1. Client sends ResetPasswordRequest (email, otp, newPassword)
   ↓
2. ProfileService.resetPassword():
   - Loads user from database
   - Validates OTP matches
   - Checks OTP not expired (15 minutes)
   - Hashes new password with BCrypt
   - Clears reset OTP fields
   ↓
3. Returns success response
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "otp": "123456",
  "newPassword": "newpassword123"
}
```

**Response:**
```json
{
  "message": "Password reset successful",
  "data": null
}
```

---

## 🔑 OAuth2 Google Login Flow

### Complete OAuth2 Flow

```
1. User clicks "Login with Google"
   ↓
2. Browser redirects to:
   https://accounts.google.com/o/oauth2/v2/auth
   ↓
3. User authenticates with Google
   ↓
4. Google redirects to:
   http://localhost:8080/api/v1.0/login/oauth2/code/google
   ↓
5. Spring Security OAuth2 Client:
   - Exchanges authorization code for access token
   - Calls CustomOAuth2UserService.loadUser()
   ↓
6. CustomOAuth2UserService:
   - Fetches user info from Google API
   - Extracts email and name
   - Checks if user exists in database
   - If not exists: Creates new user with:
     * email from Google
     * name from Google
     * userID = UUID
     * isAccountVerified = true (auto-verified)
     * password = "" (no password for OAuth users)
   ↓
7. OAuth2SuccessHandler.onAuthenticationSuccess():
   - Generates JWT token for user
   - Redirects to frontend:
     http://localhost:5173/oauth-success?token=<jwt-token>
   ↓
8. Frontend receives token and stores it
```

### OAuth2 Configuration

**Provider:** Google
- **Client ID**: Configured in application.properties
- **Client Secret**: Configured in application.properties
- **Scopes**: email, profile
- **User Info Endpoint**: `https://www.googleapis.com/oauth2/v3/userinfo`

---

## 📧 Email Service Flow

### Email Configuration

**SMTP Server:** Gmail (smtp.gmail.com:587)
- **Authentication**: Required
- **TLS**: Enabled
- **From Email**: joshidipanshu71@gmail.com

### Email Types

#### 1. Welcome Email
**Trigger:** User registration
**Content:**
```
Subject: Welcome to our Platform
Body: Hello {name},
      Thanks for registering with us!
      Regards, Authify
```

#### 2. Verification OTP Email
**Trigger:** User requests email verification
**Content:**
```
Subject: Account Verification OTP
Body: Your OTP is {otp}. Verify your account using this OTP.
```

#### 3. Password Reset OTP Email
**Trigger:** User requests password reset
**Content:**
```
Subject: Password Reset OTP
Body: Your OTP for resetting your password is {otp}. 
      Use this OTP to proceed with resetting your password.
```

---

## 🎫 JWT Token Flow

### Token Generation (JwtUtil.generateToken())

```
1. Receives UserDetails (email)
   ↓
2. Creates claims map (empty for now)
   ↓
3. Sets token properties:
   - Subject: user email
   - Issued At: current time
   - Expiration: current time + 10 hours
   ↓
4. Signs token with HMAC-SHA256 using secret key
   ↓
5. Returns compact JWT string
```

### Token Structure

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "user@example.com",
  "iat": 1234567890,
  "exp": 1234601490
}
```

**Secret Key:** `thisisthesecretkeyievercreatedinmydevelopmentcareer`

### Token Validation (JwtUtil.validateToken())

```
1. Extract email from token
   ↓
2. Check token expiration
   ↓
3. Verify email matches UserDetails username
   ↓
4. Verify token signature
   ↓
5. Return true if all validations pass
```

### Token Extraction (JwtRequestFilter)

**Priority Order:**
1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Cookie**: `jwt` cookie value

---

## 🧩 Component Details

### 1. Controllers

#### AuthController
- Handles authentication operations
- Endpoints: login, logout, is-authenticated, send-reset-otp, reset-password, send-otp, verify-otp

#### ProfileController
- Handles user profile operations
- Endpoints: register, profile

### 2. Services

#### AppUserDetailService
- Implements Spring Security's UserDetailsService
- Loads user from database by email
- Returns UserDetails for authentication

#### CustomOAuth2UserService
- Extends DefaultOAuth2UserService
- Handles OAuth2 user loading
- Auto-creates users from OAuth2 login

#### ProfileService / ProfileServiceImpl
- User profile management
- OTP generation and validation
- Password reset logic
- Email verification logic

#### EmailService
- Sends emails via Gmail SMTP
- Three email types: welcome, verification OTP, reset OTP

### 3. Filters

#### JwtRequestFilter
- Extends OncePerRequestFilter
- Intercepts all requests
- Extracts and validates JWT tokens
- Sets SecurityContext for authenticated users

### 4. Configuration

#### SecurityConfig
- Configures Spring Security
- Sets up CORS
- Configures public/protected endpoints
- Sets up OAuth2 login
- Configures authentication manager

#### CustomAuthenticationEntryPoint
- Handles unauthenticated requests
- Returns 401 with JSON error message

#### OAuth2SuccessHandler
- Handles successful OAuth2 authentication
- Generates JWT token
- Redirects to frontend with token

### 5. Utilities

#### JwtUtil
- Token generation
- Token validation
- Token parsing
- Email extraction from token

### 6. Exception Handling

#### GlobalExceptionHandler
- Handles validation errors (@Valid)
- Handles RuntimeException
- Generic exception handler
- Returns standardized ApiResponse format

---

## 🔄 Complete User Journey Flows

### Flow 1: New User Registration & Verification

```
1. POST /register
   - User provides name, email, password
   - System creates account (unverified)
   - Welcome email sent
   ↓
2. POST /login
   - User logs in with credentials
   - Receives JWT token
   ↓
3. POST /send-otp
   - User requests verification OTP
   - OTP sent to email (valid for 24 hours)
   ↓
4. POST /verify-otp
   - User submits OTP
   - Account verified (isAccountVerified = true)
```

### Flow 2: Password Reset

```
1. POST /send-reset-otp?email=user@example.com
   - System generates OTP (valid for 15 minutes)
   - OTP sent to email
   ↓
2. POST /reset-password
   - User provides email, OTP, new password
   - System validates OTP
   - Password updated
   - OTP cleared
```

### Flow 3: OAuth2 Google Login

```
1. User clicks "Login with Google"
   ↓
2. Redirected to Google login
   ↓
3. User authenticates with Google
   ↓
4. Google redirects back with code
   ↓
5. System exchanges code for user info
   ↓
6. User auto-created if doesn't exist (verified)
   ↓
7. JWT token generated
   ↓
8. Redirected to frontend with token
```

### Flow 4: Protected Resource Access

```
1. Client sends request with JWT token
   (in Authorization header or cookie)
   ↓
2. JwtRequestFilter intercepts
   ↓
3. Extracts token
   ↓
4. Validates token (signature + expiration)
   ↓
5. Loads user from database
   ↓
6. Sets SecurityContext
   ↓
7. Controller processes request
   ↓
8. Returns response
```

---

## ⚙️ Configuration Details

### application.properties

**Application:**
- Name: LockIn
- Context Path: /api/v1.0
- Port: 8080 (default)

**Database:**
- URL: jdbc:mysql://localhost:3306/authify_app
- Username: root
- Password: rootPassword
- Driver: com.mysql.cj.jdbc.Driver
- Hibernate DDL: update (auto-create/update tables)

**JWT:**
- Secret Key: thisisthesecretkeyievercreatedinmydevelopmentcareer
- Expiration: 36000000 ms (10 hours)

**Email (Gmail SMTP):**
- Host: smtp.gmail.com
- Port: 587
- Username: joshidipanshu71@gmail.com
- Password: qmju nvhb ptct kumy
- TLS: Enabled

**OAuth2 Google:**
- Client ID: 1073124509328-s6hasjun75ifrei1f3k8899grd5mpdoh.apps.googleusercontent.com
- Client Secret: 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
- Scopes: email, profile
- Redirect URI: http://localhost:8080/api/v1.0/login/oauth2/code/google

---

## 🛡️ Security Features

1. **Password Hashing**: BCrypt (one-way hashing)
2. **JWT Tokens**: Stateless authentication
3. **HTTP-Only Cookies**: Prevents XSS attacks
4. **CORS Protection**: Restricted to specific origin
5. **OTP Expiration**: Time-limited OTPs
6. **Token Expiration**: 10-hour token validity
7. **Input Validation**: Jakarta Validation annotations
8. **Exception Handling**: Standardized error responses

---

## 📊 Data Flow Summary

```
Client Request
    ↓
[CORS Filter]
    ↓
[JWT Filter] → Extract Token → Validate → Set SecurityContext
    ↓
[Security Filter Chain] → Check Authorization
    ↓
[Controller] → Validate Input
    ↓
[Service] → Business Logic
    ↓
[Repository] → Database Query
    ↓
[Entity] → Database Table
    ↓
[Response] → JSON Response
```

---

## 🎯 Key Design Patterns

1. **Layered Architecture**: Controller → Service → Repository
2. **DTO Pattern**: Separate request/response objects (IO package)
3. **Builder Pattern**: Used in Entity classes (Lombok)
4. **Filter Pattern**: JWT authentication filter
5. **Strategy Pattern**: OAuth2 user service
6. **Dependency Injection**: Spring's @Autowired/@RequiredArgsConstructor

---

## 🔍 Error Handling Flow

```
Exception occurs
    ↓
[GlobalExceptionHandler] intercepts
    ↓
Determines exception type:
    ├─ MethodArgumentNotValidException → 400 Bad Request
    ├─ RuntimeException → 400 Bad Request
    └─ Exception → 500 Internal Server Error
    ↓
Returns ApiResponse with error message
```

---

## 📝 Notes

1. **OTP Expiration Times:**
   - Verification OTP: 24 hours
   - Reset OTP: 15 minutes

2. **Token Storage:**
   - Server: No token storage (stateless)
   - Client: JWT in cookie or Authorization header

3. **Password Requirements:**
   - Minimum 6 characters (enforced by validation)

4. **Email Uniqueness:**
   - Enforced at database level (unique constraint)
   - Checked before user creation

5. **OAuth2 Users:**
   - Auto-verified (isAccountVerified = true)
   - No password stored (empty string)

---

## 🚀 Deployment Considerations

1. **Environment Variables**: Move sensitive data (DB password, JWT secret, email credentials) to environment variables
2. **HTTPS**: Enable HTTPS in production
3. **CORS**: Update allowed origins for production frontend
4. **Database**: Use connection pooling in production
5. **Logging**: Configure appropriate log levels
6. **Monitoring**: Add health checks and metrics

---

**End of Complete Project Flow Documentation**

