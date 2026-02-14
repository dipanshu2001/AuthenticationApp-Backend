package com.Authify.LockIn.IO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.io.StringReader;

@Data
public class VerifyOTPRequest {
    @NotBlank(message = "OTP is required")
    @Pattern(
            regexp = "^\\d{6}$",
            message = "OTP must be exactly 6 digits"
    )
    private String otp;
}
