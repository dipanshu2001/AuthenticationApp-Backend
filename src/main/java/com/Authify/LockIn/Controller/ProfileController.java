package com.Authify.LockIn.Controller;

import com.Authify.LockIn.IO.ApiResponse;
import com.Authify.LockIn.IO.ProfileRequest;
import com.Authify.LockIn.IO.ProfileResponse;
import com.Authify.LockIn.IO.ProfileUpdateRequest;
import com.Authify.LockIn.Service.EmailService;
import com.Authify.LockIn.Service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
        try {
            emailService.sendWelcomeEmail(response.getEmail(),response.getName());
            return new ApiResponse<>("User registered successfully! Welcome email sent.",response);
        } catch (Exception e) {
            // User is already created, so return success even if email fails
            return new ApiResponse<>("User registered successfully! Welcome email could not be sent.",response);
        }
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
