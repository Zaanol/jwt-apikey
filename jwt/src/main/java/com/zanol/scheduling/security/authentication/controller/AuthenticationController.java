package com.zanol.scheduling.security.authentication.controller;

import com.zanol.scheduling.security.authentication.model.AuthRequest;
import com.zanol.scheduling.security.authentication.model.AuthResponse;
import com.zanol.scheduling.security.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/generateToken")
    public ResponseEntity<?> generateToken(@RequestBody AuthRequest authRequest) throws Exception {
        final String token = authenticationService.generateToken(authRequest);

        return ResponseEntity.ok(new AuthResponse(token));
    }
}