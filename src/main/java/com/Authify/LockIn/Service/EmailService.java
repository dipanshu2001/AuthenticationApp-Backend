package com.Authify.LockIn.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String fromEmail;
    public void sendWelcomeEmail(String toEmail,String name){
        SimpleMailMessage message=new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Welcome to our Platform");
        message.setText("Hello "+name+",\n\nThanks for registering with us!\n\nRegards, \nAuthify");
        mailSender.send(message);
    }
    public void sendResetOTPEmail(String toEmail,String otp){
        SimpleMailMessage message=new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Password Reset OTP");
        message.setText("Your OTP for resetting your password is "+otp+". Use this OTP to proceed with resetting your password");
        mailSender.send(message);
    }
    public void sendOtpEmail(String toEmail,String otp){
        SimpleMailMessage message=new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Account Verification OTP");
        message.setText("Yout OTP is "+ otp +". Verify your account using this OTP. ");
        mailSender.send(message);
    }
}
