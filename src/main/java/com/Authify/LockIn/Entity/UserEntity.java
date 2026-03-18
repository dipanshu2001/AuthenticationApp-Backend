package com.Authify.LockIn.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.sql.Timestamp;

@Entity
@Table(name="tbl_users")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String userID;
    private String name;
    @Column(unique = true)
    private String email;
    private String password;
    private String verifyOtp;
    private boolean isAccountVerified;
    private Long verifyOtpExpiredAt;
    private int verifyOtpAttempts;
    private String resetOtp;
    private Long resetOtpExpiredAt;
    private int resetOtpAttempts;
    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdAt;
    @UpdateTimestamp
    private Timestamp updatedAt;
    private String role;

}
