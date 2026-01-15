package com.Authify.LockIn.Controller;

import com.Authify.LockIn.IO.ApiResponse;
import com.Authify.LockIn.IO.ProfileRequest;
import com.Authify.LockIn.IO.ProfileResponse;
import com.Authify.LockIn.IO.ProfileUpdateRequest;
import com.Authify.LockIn.Service.EmailService;
import com.Authify.LockIn.Service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/profile")
public class ProfileController {
    private final ProfileService profileService;
    private final EmailService emailService;
    @PostMapping("/register")
    public ApiResponse<ProfileResponse> register(@Valid @RequestBody ProfileRequest request){
        ProfileResponse response=profileService.createProfile(request);
       emailService.sendWelcomeEmail(response.getEmail(),response.getName());
        // send Welcome email
        return new ApiResponse<>("User registered successfully! Welcome email sent.",response);
    }
    @GetMapping("/profile")
    public ApiResponse<ProfileResponse> getProfile(@CurrentSecurityContext(expression = "authentication?.name")String email){
        ProfileResponse profile= profileService.getProfile(email);
        return new ApiResponse<>("Profile fetched successfully!",profile);
    }
    @PutMapping("/profile")
    public ApiResponse<ProfileResponse> updateProfile(
            @CurrentSecurityContext(expression = "authentication?.name")String email,
            @RequestBody ProfileUpdateRequest request){
        ProfileResponse updated=profileService.updateProfile(email,request);
        return new ApiResponse<>("Profile updated successfully",updated);
    }

}
