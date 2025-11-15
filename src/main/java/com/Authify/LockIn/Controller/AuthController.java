package com.Authify.LockIn.Controller;

import com.Authify.LockIn.IO.ApiResponse;
import com.Authify.LockIn.IO.ResetPasswordRequest;
import com.Authify.LockIn.Service.ProfileService;
import com.Authify.LockIn.Util.JwtUtil;
import com.Authify.LockIn.IO.AuthRequest;
import com.Authify.LockIn.IO.AuthResponse;
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
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final AppUserDetailService appUserDetailService;
    private final JwtUtil jwtUtil;
    private final ProfileService profileService;
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request){
        try {
            authenticate(request.getEmail(), request.getPassword());

            final UserDetails userDetails = appUserDetailService.loadUserByUsername(request.getEmail());
            final String jwtToken = jwtUtil.generateToken(userDetails);

            ResponseCookie cookie = ResponseCookie.from("jwt", jwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("strict")
                    .build();

            AuthResponse authData = new AuthResponse(request.getEmail(), jwtToken);
            ApiResponse<AuthResponse> response = new ApiResponse<>("Login successful", authData);

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(response);
        }
        catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("Email or Password is incorrect",null));
        }
        catch (DisabledException e){

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("Account is disabled",null));
        }
        catch (Exception e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("Authentication Failed",null));
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
    public ResponseEntity<?> logout() {
        ResponseCookie cookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .sameSite("strict")
                .build();
        ApiResponse<Void> response = new ApiResponse<>("Logged out successfully", null);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(response);
    }

}
