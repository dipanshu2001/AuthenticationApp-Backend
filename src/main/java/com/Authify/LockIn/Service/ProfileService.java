package com.Authify.LockIn.Service;

import com.Authify.LockIn.IO.ProfileRequest;
import com.Authify.LockIn.IO.ProfileResponse;
import com.Authify.LockIn.IO.ProfileUpdateRequest;

public interface ProfileService {
     ProfileResponse createProfile(ProfileRequest request);
     ProfileResponse getProfile(String email);
     void sendResetOTP(String email);
     void resetPassword(String email,String otp,String newPassword);
     void sendOTP(String email);
     void verifyOTP(String email,String otp);
     String getLoggedInUserId(String email);
     String getEmailByUserId(String userId);
     ProfileResponse updateProfile(String email, ProfileUpdateRequest request);
}
