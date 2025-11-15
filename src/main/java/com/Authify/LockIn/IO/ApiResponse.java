package com.Authify.LockIn.IO;

import lombok.*;

@Data
@AllArgsConstructor
public class ApiResponse <T>{
    private String message;
    private T data;

}
