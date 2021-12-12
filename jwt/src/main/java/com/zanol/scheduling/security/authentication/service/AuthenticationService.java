package com.zanol.scheduling.security.authentication.service;

import com.zanol.scheduling.security.authentication.model.AuthRequest;

public interface AuthenticationService {
    String generateToken(AuthRequest authRequest);
}