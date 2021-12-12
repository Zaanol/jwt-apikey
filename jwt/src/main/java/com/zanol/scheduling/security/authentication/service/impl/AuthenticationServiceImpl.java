package com.zanol.scheduling.security.authentication.service.impl;

import com.zanol.scheduling.security.authentication.service.MyUserDetailsService;
import com.zanol.scheduling.security.authentication.Authenticator;
import com.zanol.scheduling.security.authentication.model.AuthRequest;
import com.zanol.scheduling.security.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private Authenticator authenticator;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Override
    public String generateToken(AuthRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getCode(), authRequest.getPassword())
        );

        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(authRequest.getCode());

        return authenticator.generateToken(userDetails);
    }
}