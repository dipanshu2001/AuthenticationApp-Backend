# Complete Method Explanations - LockIn Project

This document provides detailed explanations of every method in the LockIn authentication system.

---

## 📋 Table of Contents

1. [Controllers](#controllers)
   - [AuthController](#authcontroller)
   - [ProfileController](#profilecontroller)
2. [Services](#services)
   - [ProfileServiceImpl](#profileserviceimpl)
   - [AppUserDetailService](#appuserdetailservice)
   - [CustomOAuth2UserService](#customoauth2userservice)
   - [EmailService](#emailservice)
3. [Configuration](#configuration)
   - [SecurityConfig](#securityconfig)
   - [CustomAuthenticationEntryPoint](#customauthenticationentrypoint)
   - [OAuth2SuccessHandler](#oauth2successhandler)
4. [Filters](#filters)
   - [JwtRequestFilter](#jwtrequestfilter)
5. [Utilities](#utilities)
   - [JwtUtil](#jwtutil)
6. [Exception Handling](#exception-handling)
   - [GlobalExceptionHandler](#globalexceptionhandler)
7. [Repositories](#repositories)
   - [UserRepository](#userrepository)

---

## Controllers

### AuthController

#### `login(@RequestBody AuthRequest request)`
**Purpose**: Authenticates a user and generates a JWT token.

**Flow**:
1. Receives `AuthRequest` containing email and password
2. Calls private `authenticate()` method to validate credentials
3. If authentication succeeds:
   - Loads `UserDetails` using `AppUserDetailService`
   - Generates JWT token using `JwtUtil.generateToken()`
   - Creates an HTTP-only cookie with the JWT token (expires in 1 day)
   - Returns `AuthResponse` with email and token
4. If authentication fails:
   - Catches `BadCredentialsException` → Returns 400 with "Email or Password is incorrect"
   - Catches `DisabledException` → Returns 401 with "Account is disabled"
   - Catches other exceptions → Returns 401 with "Authentication Failed"

**Returns**: `ResponseEntity<?>` with JWT token in both cookie and response body

---

#### `authenticate(String email, String password)` (private)
**Purpose**: Internal method to authenticate user credentials.

**Flow**:
1. Creates a `UsernamePasswordAuthenticationToken` with email and password
2. Passes it to `AuthenticationManager.authenticate()`
3. Spring Security validates credentials using `AppUserDetailService` and `PasswordEncoder`
4. Throws exception if authentication fails

**Note**: This is a private helper method used only by `login()`

---

#### `isAuthenticated(@CurrentSecurityContext String email)`
**Purpose**: Checks if the current user is authenticated.

**Flow**:
1. Extracts email from `SecurityContext` using `@CurrentSecurityContext` annotation
2. If email is not null, user is authenticated
3. Returns boolean indicating authentication status

**Returns**: `ResponseEntity<?>` with `ApiResponse` containing true/false

**Note**: Requires JWT token to be present (validated by `JwtRequestFilter`)

---

#### `sendResetOTP(@RequestParam String email)`
**Purpose**: Sends a password reset OTP to the user's email.

**Flow**:
1. Receives email as query parameter
2. Delegates to `ProfileService.sendResetOTP(email)`
3. Returns success message

**Returns**: `ApiResponse<Void>` with success message

**Note**: This is a public endpoint (no authentication required)

---

#### `resetPassword(@Valid @RequestBody ResetPasswordRequest request)`
**Purpose**: Resets user password using OTP verification.

**Flow**:
1. Receives `ResetPasswordRequest` with email, OTP, and new password
2. Validates request using `@Valid` annotation
3. Delegates to `ProfileService.resetPassword()`
4. Returns success message

**Returns**: `ApiResponse<Void>` with success message

**Note**: This is a public endpoint (no authentication required)

---

#### `sendVerifyOtp(@CurrentSecurityContext String email)`
**Purpose**: Sends email verification OTP to authenticated user.

**Flow**:
1. Extracts email from `SecurityContext` (user must be authenticated)
2. Delegates to `ProfileService.sendOTP(email)`
3. Returns success message

**Returns**: `ApiResponse<Void>` with success message

**Note**: Requires JWT authentication

---

#### `verifyEmail(@RequestBody Map<String,Object> request, @CurrentSecurityContext String email)`
**Purpose**: Verifies user email using OTP.

**Flow**:
1. Extracts email from `SecurityContext`
2. Extracts OTP from request body map
3. Validates OTP is present (throws `RuntimeException` if missing)
4. Delegates to `ProfileService.verifyOTP(email, otp)`
5. Returns success message

**Returns**: `ApiResponse<Void>` with success message

**Note**: Requires JWT authentication

---

#### `logout()`
**Purpose**: Logs out the user by clearing the JWT cookie.

**Flow**:
1. Creates an empty JWT cookie with `maxAge = 0` (immediately expires)
2. Sets cookie properties (httpOnly, path, sameSite)
3. Returns success message with cookie in response header

**Returns**: `ResponseEntity<?>` with expired cookie header

**Note**: This is a public endpoint

---

### ProfileController

#### `register(@Valid @RequestBody ProfileRequest request)`
**Purpose**: Registers a new user account.

**Flow**:
1. Receives `ProfileRequest` with name, email, and password
2. Validates request using `@Valid` annotation
3. Calls `ProfileService.createProfile()` to create user
4. Sends welcome email using `EmailService.sendWelcomeEmail()`
5. Returns `ProfileResponse` with user details

**Returns**: `ApiResponse<ProfileResponse>` with user information

**Note**: This is a public endpoint

---

#### `getProfile(@CurrentSecurityContext String email)`
**Purpose**: Retrieves the authenticated user's profile.

**Flow**:
1. Extracts email from `SecurityContext` (user must be authenticated)
2. Calls `ProfileService.getProfile(email)` to fetch user data
3. Returns `ProfileResponse` with user details

**Returns**: `ApiResponse<ProfileResponse>` with user profile

**Note**: Requires JWT authentication

---

## Services

### ProfileServiceImpl

#### `createProfile(ProfileRequest request)`
**Purpose**: Creates a new user profile in the database.

**Flow**:
1. Converts `ProfileRequest` to `UserEntity` using private `convertToUserEntity()` method
2. Checks if email already exists using `userRepository.existsByEmail()`
3. If email doesn't exist:
   - Saves new user to database
   - Returns `ProfileResponse` using private `convertToProfileResponse()` method
4. If email exists:
   - Throws `ResponseStatusException` with HTTP 409 CONFLICT

**Returns**: `ProfileResponse` with user details

**Throws**: `ResponseStatusException` if email already exists

---

#### `getProfile(String email)`
**Purpose**: Retrieves user profile by email.

**Flow**:
1. Finds user by email using `userRepository.findByEmail()`
2. If user not found, throws `UsernameNotFoundException`
3. Converts `UserEntity` to `ProfileResponse` using private `convertToProfileResponse()` method
4. Returns profile response

**Returns**: `ProfileResponse` with user details

**Throws**: `UsernameNotFoundException` if user doesn't exist

---

#### `sendResetOTP(String email)`
**Purpose**: Generates and sends password reset OTP.

**Flow**:
1. Finds user by email (throws `UsernameNotFoundException` if not found)
2. Generates 6-digit OTP (100000-999999) using `ThreadLocalRandom`
3. Calculates expiry time: current time + 15 minutes (in milliseconds)
4. Updates user entity with OTP and expiry time
5. Saves user to database
6. Sends OTP email using `EmailService.sendResetOTPEmail()`
7. If email sending fails, throws `RuntimeException`

**Throws**: 
- `UsernameNotFoundException` if user doesn't exist
- `RuntimeException` if email sending fails

---

#### `resetPassword(String email, String otp, String newPassword)`
**Purpose**: Resets user password after OTP verification.

**Flow**:
1. Finds user by email (throws `UsernameNotFoundException` if not found)
2. Validates OTP:
   - Checks if `resetOtp` is not null
   - Compares provided OTP with stored OTP
   - Throws `RuntimeException("Invalid OTP")` if mismatch
3. Validates OTP expiry:
   - Compares `resetOtpExpiredAt` with current time
   - Throws `RuntimeException("OTP expired")` if expired
4. Hashes new password using `PasswordEncoder`
5. Updates user password
6. Clears OTP fields (sets to null and 0)
7. Saves user to database

**Throws**:
- `UsernameNotFoundException` if user doesn't exist
- `RuntimeException` if OTP is invalid or expired

---

#### `sendOTP(String email)`
**Purpose**: Generates and sends email verification OTP.

**Flow**:
1. Finds user by email (throws `UsernameNotFoundException` if not found)
2. Checks if account is already verified:
   - If `isAccountVerified` is true, returns early (no OTP sent)
3. Generates 6-digit OTP (100000-999999) using `ThreadLocalRandom`
4. Calculates expiry time: current time + 24 hours (in milliseconds)
5. Updates user entity with OTP and expiry time
6. Saves user to database
7. Sends OTP email using `EmailService.sendOtpEmail()`
8. If email sending fails, throws `RuntimeException`

**Throws**:
- `UsernameNotFoundException` if user doesn't exist
- `RuntimeException` if email sending fails

**Note**: Returns silently if account is already verified

---

#### `verifyOTP(String email, String otp)`
**Purpose**: Verifies user email using OTP.

**Flow**:
1. Finds user by email (throws `UsernameNotFoundException` if not found)
2. Validates OTP:
   - Checks if `verifyOtp` is not null
   - Compares provided OTP with stored OTP
   - Throws `RuntimeException("Invalid OTP")` if mismatch
3. Validates OTP expiry:
   - Compares `verifyOtpExpiredAt` with current time
   - Throws `RuntimeException("OTP expired")` if expired
4. Sets `isAccountVerified` to true
5. Clears OTP fields (sets to null and 0)
6. Saves user to database

**Throws**:
- `UsernameNotFoundException` if user doesn't exist
- `RuntimeException` if OTP is invalid or expired

---

#### `getLoggedInUserId(String email)`
**Purpose**: Retrieves the userID (UUID) for a given email.

**Flow**:
1. Finds user by email (throws `UsernameNotFoundException` if not found)
2. Returns the `userID` field (UUID string)

**Returns**: `String` containing the userID

**Throws**: `UsernameNotFoundException` if user doesn't exist

---

#### `convertToProfileResponse(UserEntity newProfile)` (private)
**Purpose**: Converts `UserEntity` to `ProfileResponse` DTO.

**Flow**:
1. Uses builder pattern to create `ProfileResponse`
2. Maps fields:
   - `name` → `name`
   - `email` → `email`
   - `userID` → `userId`
   - `isAccountVerified` → `isAccountVerified`
3. Returns built `ProfileResponse`

**Returns**: `ProfileResponse` object

---

#### `convertToUserEntity(ProfileRequest request)` (private)
**Purpose**: Converts `ProfileRequest` to `UserEntity`.

**Flow**:
1. Uses builder pattern to create `UserEntity`
2. Maps and sets fields:
   - `email` from request
   - `name` from request
   - `userID` = new UUID (generated)
   - `password` = hashed password using `PasswordEncoder`
   - `isAccountVerified` = false (new users are unverified)
   - `resetOtpExpiredAt` = 0
   - `verifyOtp` = null
   - `verifyOtpExpiredAt` = 0
   - `resetOtp` = null
3. Returns built `UserEntity`

**Returns**: `UserEntity` object ready to be saved

---

### AppUserDetailService

#### `loadUserByUsername(String email)`
**Purpose**: Implements Spring Security's `UserDetailsService` interface to load user for authentication.

**Flow**:
1. Finds user by email using `userRepository.findByEmail()`
2. If user not found, throws `UsernameNotFoundException`
3. Creates Spring Security `User` object with:
   - Username: user's email
   - Password: user's hashed password
   - Authorities: empty list (no roles defined)
4. Returns `UserDetails` object

**Returns**: `UserDetails` object for Spring Security authentication

**Throws**: `UsernameNotFoundException` if user doesn't exist

**Note**: This method is called by Spring Security's `AuthenticationManager` during login

---

### CustomOAuth2UserService

#### `loadUser(OAuth2UserRequest userRequest)`
**Purpose**: Handles OAuth2 user loading and auto-creates users from Google login.

**Flow**:
1. Calls parent class `super.loadUser()` to fetch OAuth2 user from Google
2. Extracts user attributes from OAuth2 user:
   - `email` from attributes map
   - `name` from attributes map
3. Checks if user exists in database using `userRepository.findByEmail()`
4. If user doesn't exist:
   - Creates new `UserEntity` with:
     * `email` from Google
     * `name` from Google
     * `userID` = new UUID
     * `isAccountVerified` = true (OAuth users are auto-verified)
     * `password` = "" (empty string, no password for OAuth users)
   - Saves new user to database
5. Returns the OAuth2 user object

**Returns**: `OAuth2User` object

**Note**: Uses `orElseGet()` to conditionally create user only if not exists

---

### EmailService

#### `sendWelcomeEmail(String toEmail, String name)`
**Purpose**: Sends welcome email to newly registered users.

**Flow**:
1. Creates `SimpleMailMessage` object
2. Sets email properties:
   - `from`: configured email address (from `application.properties`)
   - `to`: recipient email
   - `subject`: "Welcome to our Platform"
   - `text`: Personalized message with user's name
3. Sends email using `JavaMailSender.send()`

**Note**: Email is sent synchronously

---

#### `sendResetOTPEmail(String toEmail, String otp)`
**Purpose**: Sends password reset OTP email.

**Flow**:
1. Creates `SimpleMailMessage` object
2. Sets email properties:
   - `from`: configured email address
   - `to`: recipient email
   - `subject`: "Password Reset OTP"
   - `text`: Message containing the OTP
3. Sends email using `JavaMailSender.send()`

---

#### `sendOtpEmail(String toEmail, String otp)`
**Purpose**: Sends email verification OTP.

**Flow**:
1. Creates `SimpleMailMessage` object
2. Sets email properties:
   - `from`: configured email address
   - `to`: recipient email
   - `subject`: "Account Verification OTP"
   - `text`: Message containing the OTP
3. Sends email using `JavaMailSender.send()`

---

## Configuration

### SecurityConfig

#### `securityFilterChain(HttpSecurity http)`
**Purpose**: Configures Spring Security filter chain with all security settings.

**Flow**:
1. Enables CORS with default configuration
2. Disables CSRF (using JWT tokens instead)
3. Configures authorization:
   - Public endpoints (permitAll): `/login`, `/register`, `/send-reset-otp`, `/reset-password`, `/logout`, `/oauth2/**`
   - All other endpoints require authentication
4. Configures OAuth2 login:
   - Sets login page to `/login`
   - Uses `CustomOAuth2UserService` for user loading
   - Uses `OAuth2SuccessHandler` for success handling
5. Sets session management to STATELESS (JWT-based)
6. Disables default logout
7. Adds `JwtRequestFilter` before `UsernamePasswordAuthenticationFilter`
8. Sets custom authentication entry point for unauthenticated requests
9. Returns configured `SecurityFilterChain`

**Returns**: `SecurityFilterChain` bean

---

#### `passwordEncoder()`
**Purpose**: Creates BCrypt password encoder bean.

**Flow**:
1. Creates new `BCryptPasswordEncoder` instance
2. Returns it as a Spring bean

**Returns**: `PasswordEncoder` bean (BCrypt implementation)

**Note**: Used throughout the application for password hashing

---

#### `corsFilter()`
**Purpose**: Creates CORS filter bean.

**Flow**:
1. Creates `CorsFilter` using `corsConfigurationSource()`
2. Returns it as a Spring bean

**Returns**: `CorsFilter` bean

---

#### `corsConfigurationSource()`
**Purpose**: Configures CORS settings.

**Flow**:
1. Creates `CorsConfiguration` object
2. Sets allowed origins: `http://localhost:5173` (frontend)
3. Sets allowed methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
4. Sets allowed headers: all headers (`*`)
5. Enables credentials (cookies, authorization headers)
6. Sets exposed headers: `Set-Cookie` (for JWT cookie)
7. Registers configuration for all paths (`/**`)
8. Returns `CorsConfigurationSource`

**Returns**: `CorsConfigurationSource` bean

---

#### `authenticationManager()`
**Purpose**: Creates custom authentication manager bean.

**Flow**:
1. Creates `DaoAuthenticationProvider` instance
2. Sets `UserDetailsService` to `appUserDetailService`
3. Sets `PasswordEncoder` to BCrypt encoder
4. Creates `ProviderManager` with the authentication provider
5. Returns it as a Spring bean

**Returns**: `AuthenticationManager` bean

**Note**: Used by `AuthController.login()` to authenticate users

---

### CustomAuthenticationEntryPoint

#### `commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)`
**Purpose**: Handles unauthenticated requests (entry point for authentication failures).

**Flow**:
1. Sets HTTP status to 401 (UNAUTHORIZED)
2. Sets content type to `application/json`
3. Writes JSON response to response writer:
   ```json
   {
     "authenticated": false,
     "message": "User is not authenticated"
   }
   ```

**Note**: Called when an unauthenticated user tries to access a protected endpoint

---

### OAuth2SuccessHandler

#### `onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)`
**Purpose**: Handles successful OAuth2 authentication and redirects to frontend with JWT token.

**Flow**:
1. Extracts `OAuth2User` from authentication principal
2. Gets email from OAuth2 user attributes
3. Creates Spring Security `User` object with:
   - Username: email
   - Password: empty string
   - Authorities: "USER"
4. Generates JWT token using `JwtUtil.generateToken()`
5. Redirects to frontend URL with token as query parameter:
   `http://localhost:5173/oauth-success?token=<jwt-token>`

**Note**: Frontend receives token in URL and must extract/store it

---

## Filters

### JwtRequestFilter

#### `doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)`
**Purpose**: Intercepts all requests to validate JWT tokens and set authentication context.

**Flow**:
1. Gets request path using `request.getServletPath()`
2. Checks if path is in `PUBLIC_URLS` list:
   - If yes: skips JWT validation, proceeds to next filter
   - If no: continues with JWT validation
3. Extracts JWT token (priority order):
   - **First**: Checks `Authorization` header for `Bearer <token>`
   - **Second**: Checks cookies for `jwt` cookie value
4. If JWT token found:
   - Extracts email from token using `JwtUtil.extractEmail()`
   - Checks if `SecurityContext` is empty
   - If empty:
     * Loads `UserDetails` using `AppUserDetailService.loadUserByUsername()`
     * Validates token using `JwtUtil.validateToken()`
     * If valid:
       - Creates `UsernamePasswordAuthenticationToken`
       - Sets authentication details
       - Sets authentication in `SecurityContextHolder`
5. Proceeds to next filter in chain

**Note**: This filter runs before Spring Security's authentication filter

---

## Utilities

### JwtUtil

#### `getSigningKey()`
**Purpose**: Generates HMAC-SHA256 signing key from secret key string.

**Flow**:
1. Gets `SECRET_KEY` from `@Value` annotation (from `application.properties`)
2. Converts secret key string to bytes
3. Creates HMAC-SHA256 key using `Keys.hmacShaKeyFor()`
4. Returns `SecretKey` object

**Returns**: `SecretKey` for JWT signing/verification

---

#### `generateToken(UserDetails userDetails)`
**Purpose**: Generates JWT token for authenticated user.

**Flow**:
1. Creates empty claims map
2. Calls private `createToken()` method with claims and username (email)
3. Returns JWT token string

**Returns**: JWT token string

---

#### `createToken(Map<String, Object> claims, String email)` (private)
**Purpose**: Creates JWT token with specified claims and email.

**Flow**:
1. Uses `Jwts.builder()` to build token
2. Sets claims map
3. Sets subject (email) using `setSubject()`
4. Sets issued at time (current time) using `setIssuedAt()`
5. Sets expiration time: current time + 10 hours using `setExpiration()`
6. Signs token with HMAC-SHA256 using `signWith()`
7. Compacts token to string using `compact()`
8. Returns JWT string

**Returns**: Compact JWT token string

---

#### `extractAllClaims(String token)` (private)
**Purpose**: Extracts all claims from JWT token.

**Flow**:
1. Creates JWT parser builder
2. Sets signing key using `getSigningKey()`
3. Parses JWT token
4. Gets claims body
5. Returns `Claims` object

**Returns**: `Claims` object containing all token claims

**Throws**: Exception if token is invalid or signature doesn't match

---

#### `extractClaim(String token, Function<Claims, T> claimsResolver)`
**Purpose**: Generic method to extract a specific claim from token.

**Flow**:
1. Extracts all claims using `extractAllClaims()`
2. Applies `claimsResolver` function to extract specific claim
3. Returns extracted claim value

**Returns**: Claim value of type `T`

---

#### `extractEmail(String token)`
**Purpose**: Extracts email (subject) from JWT token.

**Flow**:
1. Uses `extractClaim()` with `Claims::getSubject` function
2. Returns email string

**Returns**: Email string (token subject)

---

#### `extractExpiration(String token)`
**Purpose**: Extracts expiration date from JWT token.

**Flow**:
1. Uses `extractClaim()` with `Claims::getExpiration` function
2. Returns expiration date

**Returns**: `Date` object representing token expiration

---

#### `isTokenExpired(String token)` (private)
**Purpose**: Checks if JWT token is expired.

**Flow**:
1. Extracts expiration date using `extractExpiration()`
2. Compares expiration date with current date
3. Returns true if expiration is before current time

**Returns**: `boolean` - true if expired, false otherwise

---

#### `validateToken(String token, UserDetails userDetails)`
**Purpose**: Validates JWT token against user details.

**Flow**:
1. Extracts email from token using `extractEmail()`
2. Compares token email with `UserDetails` username
3. Checks if token is expired using `isTokenExpired()`
4. Returns true only if:
   - Email matches user details username
   - Token is not expired

**Returns**: `boolean` - true if token is valid, false otherwise

**Note**: This method does NOT verify the signature (that's done during `extractAllClaims()`)

---

## Exception Handling

### GlobalExceptionHandler

#### `handleValidationError(MethodArgumentNotValidException ex)`
**Purpose**: Handles validation errors from `@Valid` annotations.

**Flow**:
1. Extracts error message from first field error
2. Gets default message from field error
3. Returns 400 Bad Request with `ApiResponse` containing error message

**Returns**: `ResponseEntity<?>` with 400 status and error message

**Note**: Triggered when request body validation fails (e.g., empty email, invalid password length)

---

#### `handleRuntime(RuntimeException ex)`
**Purpose**: Handles custom application runtime exceptions.

**Flow**:
1. Gets exception message
2. Returns 400 Bad Request with `ApiResponse` containing exception message

**Returns**: `ResponseEntity<?>` with 400 status and exception message

**Note**: Catches exceptions like "Invalid OTP", "OTP expired", "Email already exists", etc.

---

#### `handleException(Exception ex)`
**Purpose**: Generic fallback exception handler for all other exceptions.

**Flow**:
1. Returns 500 Internal Server Error
2. Returns generic error message: "Something went wrong"

**Returns**: `ResponseEntity<?>` with 500 status and generic message

**Note**: Catches any exception not handled by other handlers

---

## Repositories

### UserRepository

#### `findByEmail(String email)`
**Purpose**: Finds user entity by email address.

**Flow**:
1. Spring Data JPA automatically generates implementation
2. Queries database for user with matching email
3. Returns `Optional<UserEntity>`

**Returns**: `Optional<UserEntity>` - empty if not found, contains user if found

**Note**: This is a Spring Data JPA query method (no implementation needed)

---

#### `existsByEmail(String email)`
**Purpose**: Checks if user exists with given email.

**Flow**:
1. Spring Data JPA automatically generates implementation
2. Queries database to check if email exists
3. Returns boolean

**Returns**: `boolean` - true if email exists, false otherwise

**Note**: This is a Spring Data JPA query method (no implementation needed)

---

## Summary

This LockIn authentication system implements:

- **User Registration & Login**: JWT-based authentication
- **Email Verification**: OTP-based verification system
- **Password Reset**: OTP-based password reset
- **OAuth2 Integration**: Google login with auto-user creation
- **Security**: JWT tokens, BCrypt password hashing, CORS protection
- **Exception Handling**: Comprehensive error handling with standardized responses

All methods work together to provide a secure, stateless authentication system using Spring Boot and Spring Security.

