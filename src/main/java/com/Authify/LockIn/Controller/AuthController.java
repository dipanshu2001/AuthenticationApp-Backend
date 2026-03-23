package com.Authify.LockIn.Controller;

import com.Authify.LockIn.Entity.RefreshToken;
import com.Authify.LockIn.IO.*;
import com.Authify.LockIn.Service.AppUserDetailService;
import com.Authify.LockIn.Service.ProfileService;
import com.Authify.LockIn.Service.RefreshTokenService;
import com.Authify.LockIn.Util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping("/v1.0/auth")
public class AuthController {

    private final AuthenticationManager  authenticationManager;
    private final AppUserDetailService   appUserDetailService;
    private final JwtUtil                jwtUtil;
    private final ProfileService         profileService;
    private final RefreshTokenService    refreshTokenService;

    // FIX: cookie.secure driven by config — not hardcoded false
    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    // ── Login ─────────────────────────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            UserDetails userDetails  = appUserDetailService.loadUserByUsername(request.getEmail());
            String accessToken  = jwtUtil.generateToken(userDetails);
            String userId       = profileService.getLoggedInUserId(request.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userId);

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, buildAccessCookie(accessToken).toString())
                    .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(refreshToken.getToken()).toString())
                    .body(new ApiResponse<>("Login successful",
                            new AuthResponse(request.getEmail(), accessToken)));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Email or Password is incorrect", null));
        } catch (DisabledException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Account is disabled", null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Authentication Failed", null));
        }
    }

    // ── Token refresh ─────────────────────────────────────────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshTokenValue) {

        if (refreshTokenValue == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Refresh token missing", null));
        }

        return refreshTokenService.validateRefreshToken(refreshTokenValue)
                .map(rt -> {
                    String email = profileService.getEmailByUserId(rt.getUserId());
                    UserDetails userDetails  = appUserDetailService.loadUserByUsername(email);
                    String newToken = jwtUtil.generateToken(userDetails);

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, buildAccessCookie(newToken).toString())
                            .body(new ApiResponse<>("Token refreshed",
                                    new AuthResponse(email, newToken)));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>("Invalid or expired refresh token", null)));
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshTokenValue) {

        if (refreshTokenValue != null) {
            refreshTokenService.revokeToken(refreshTokenValue);
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearAccessCookie().toString())
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(new ApiResponse<>("Logged out successfully", null));
    }

    // ── Auth status ───────────────────────────────────────────────────────────

    @GetMapping("/is-authenticated")
    public ResponseEntity<?> isAuthenticated(
            @CurrentSecurityContext(expression = "authentication?.name") String email) {
        return ResponseEntity.ok(new ApiResponse<>("Authentication status fetched", email != null));
    }

    // ── Password reset ────────────────────────────────────────────────────────

    @PostMapping("/send-reset-otp")
    public ApiResponse<Void> sendResetOTP(@RequestParam String email) {
        profileService.sendResetOTP(email);
        return new ApiResponse<>("Reset OTP sent to " + email, null);
    }

    @PostMapping("/reset-password")
    public ApiResponse<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        profileService.resetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());
        return new ApiResponse<>("Password reset successful", null);
    }

    // ── Email verification ────────────────────────────────────────────────────

    @PostMapping("/send-otp")
    public ApiResponse<Void> sendVerifyOtp(
            @CurrentSecurityContext(expression = "authentication?.name") String email) {
        profileService.sendOTP(email);
        return new ApiResponse<>("Verification OTP sent successfully", null);
    }

    @PostMapping("/verify-otp")
    public ApiResponse<Void> verifyEmail(
            @Valid @RequestBody VerifyOTPRequest request,
            @CurrentSecurityContext(expression = "authentication?.name") String email) {
        if (request.getOtp() == null) {
            throw new RuntimeException("OTP missing!");
        }
        profileService.verifyOTP(email, request.getOtp());
        return new ApiResponse<>("Email verified successfully", null);
    }

    // ── Account operations (FIX: delegated to service layer) ─────────────────

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @CurrentSecurityContext(expression = "authentication?.name") String email,
            @RequestBody ChangePasswordRequest body) {

        if (body.getCurrentPassword() == null || body.getNewPassword() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Both current and new passwords are required", null));
        }

        profileService.changePassword(email, body.getCurrentPassword(), body.getNewPassword());
        return ResponseEntity.ok(new ApiResponse<>("Password changed successfully", null));
    }

    @PostMapping("/account/delete")
    public ResponseEntity<?> deleteAccount(
            @CurrentSecurityContext(expression = "authentication?.name") String email,
            @RequestBody DeleteAccountRequest request) {

        if (request.getPassword() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Password is required", null));
        }

        profileService.deleteAccount(email, request.getPassword());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearAccessCookie().toString())
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(new ApiResponse<>("Account deleted successfully", null));
    }

    // ── Cookie builders ───────────────────────────────────────────────────────

    private ResponseCookie buildAccessCookie(String token) {
        return ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(Duration.ofMinutes(15))
               // .sameSite("Lax")
                .build();
    }

    private ResponseCookie buildRefreshCookie(String token) {
        return ResponseCookie.from("refresh_token", token)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/v1.0/auth")
                .maxAge(Duration.ofDays(7))
             //   .sameSite("Lax")
                .build();
    }

    private ResponseCookie clearAccessCookie() {
        return ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(0)
              //  .sameSite("Lax")
                .build();
    }

    private ResponseCookie clearRefreshCookie() {
        return ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/v1.0/auth")
                .maxAge(0)
              //  .sameSite("Lax")
                .build();
    }
}