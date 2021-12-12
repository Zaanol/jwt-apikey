package com.zanol.scheduling.security.authentication.service;

import com.zanol.scheduling.user.model.User;
import com.zanol.scheduling.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String code) throws UsernameNotFoundException {
        Optional<User> opUser = userService.getUserByCode(code);

        if (opUser.isPresent()) {
            User user = opUser.get();

            return new org.springframework.security.core.userdetails.User(code, user.getPassword(), new ArrayList<>());
        } else {
            throw new RuntimeException("User not found!");
        }
    }
}