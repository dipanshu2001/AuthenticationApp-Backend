package com.Authify.LockIn.Controller;

import com.Authify.LockIn.Entity.RefreshToken;
import com.Authify.LockIn.Entity.UserEntity;
import com.Authify.LockIn.IO.*;
import com.Authify.LockIn.Repository.UserRepository;
import com.Authify.LockIn.Service.ProfileService;
import com.Authify.LockIn.Service.RefreshTokenService;
import com.Authify.LockIn.Util.JwtUtil;
import com.Authify.LockIn.Service.AppUserDetailService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final AppUserDetailService appUserDetailService;
    private final JwtUtil jwtUtil;
    private final ProfileService profileService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            authenticate(request.getEmail(), request.getPassword());

            UserDetails userDetails = appUserDetailService.loadUserByUsername(request.getEmail());
            String accessToken = jwtUtil.generateToken(userDetails);

            String userId = profileService.getLoggedInUserId(request.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userId);

            ResponseCookie accessCookie = ResponseCookie.from("jwt", accessToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofMinutes(15))
                    .sameSite("strict")
                    .build();

            // Refresh token cookie (long‑lived)
            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken.getToken())
                    .httpOnly(true)
                    .path("/auth")
                    .maxAge(Duration.ofDays(7))
                    .sameSite("strict")
                    .build();

            AuthResponse authData = new AuthResponse(request.getEmail(), accessToken);
            ApiResponse<AuthResponse> response = new ApiResponse<>("Login successful", authData);

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                    .body(response);
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

    private void authenticate(String email,String password){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
    }
    @GetMapping("/is-authenticated")
    public ResponseEntity<?> isAuthenticated(@CurrentSecurityContext(expression = "authentication?.name")String email){
        return ResponseEntity.ok(new ApiResponse(" Authentication status fetched",email!=null));
    }
    @PostMapping("/send-reset-otp")
    public ApiResponse<Void> sendResetOTP(@RequestParam String email){
        profileService.sendResetOTP(email);
        return new ApiResponse<>("Reset OTP sent to "+email,null);
    }
    @PostMapping("/reset-password")
    public ApiResponse<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request){
        profileService.resetPassword(request.getEmail(),request.getOtp(), request.getNewPassword());
        return new ApiResponse<>("Password reset successful",null);

    }
    @PostMapping("/send-otp")
    public ApiResponse<Void> sendVerifyOtp(@CurrentSecurityContext(expression = "authentication?.name")String email){
        profileService.sendOTP(email);
        return new ApiResponse<>("Verification OTP sent successfully",null);
    }
    @PostMapping("/verify-otp")
    public ApiResponse<Void> verifyEmail(@RequestBody Map<String,Object>request,@CurrentSecurityContext(expression = "authentication?.name")String email){
        if(request.get("otp")==null){
            throw new RuntimeException("OTP missing!");
        }
        profileService.verifyOTP(email,request.get("otp").toString());
        return new ApiResponse<>("Email verified successfully",null);
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshTokenValue) {

        if (refreshTokenValue != null) {
            refreshTokenService.revokeToken(refreshTokenValue);
        }

        ResponseCookie clearAccess = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .sameSite("strict")
                .build();

        ResponseCookie clearRefresh = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .path("/auth")
                .maxAge(0)
                .sameSite("strict")
                .build();

        ApiResponse<Void> response = new ApiResponse<>("Logged out successfully", null);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearAccess.toString())
                .header(HttpHeaders.SET_COOKIE, clearRefresh.toString())
                .body(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshTokenValue) {

        if (refreshTokenValue == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Refresh token missing", null));
        }

        return refreshTokenService.validateRefreshToken(refreshTokenValue)
                .map(rt -> {
                    String userId = rt.getUserId();
                    String email = profileService.getEmailByUserId(userId);

                    UserDetails userDetails = appUserDetailService.loadUserByUsername(email);
                    String newAccessToken = jwtUtil.generateToken(userDetails);

                    ResponseCookie accessCookie = ResponseCookie.from("jwt", newAccessToken)
                            .httpOnly(true)
                            .path("/")
                            .maxAge(Duration.ofMinutes(15))
                            .sameSite("strict")
                            .build();

                    AuthResponse data = new AuthResponse(email, newAccessToken);
                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                            .body(new ApiResponse<>("Token refreshed", data));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>("Invalid or expired refresh token", null)));
    }
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @CurrentSecurityContext(expression = "authentication?.name") String email,
            @RequestBody ChangePasswordRequest body) {

        if (body.getCurrentPassword() == null || body.getNewPassword() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Both current and new passwords are required", null));
        }

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        if (!passwordEncoder.matches(body.getCurrentPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Current password is incorrect", null));
        }
        user.setPassword(passwordEncoder.encode(body.getNewPassword()));
        userRepository.save(user);
        refreshTokenService.revokeAllForUser(user.getUserID());

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

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Password is incorrect", null));
        }

        userRepository.delete(user);

        ResponseCookie clearAccess = ResponseCookie.from("jwt", "")
                .httpOnly(true).path("/").maxAge(0).sameSite("strict").build();
        ResponseCookie clearRefresh = ResponseCookie.from("refresh_token", "")
                .httpOnly(true).path("/auth").maxAge(0).sameSite("strict").build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearAccess.toString())
                .header(HttpHeaders.SET_COOKIE, clearRefresh.toString())
                .body(new ApiResponse<>("Account deleted successfully", null));
    }

}
