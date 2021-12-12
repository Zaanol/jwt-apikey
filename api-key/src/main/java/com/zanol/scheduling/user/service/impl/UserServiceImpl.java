package com.zanol.scheduling.user.service.impl;

import com.zanol.scheduling.user.model.User;
import com.zanol.scheduling.user.repository.UserRepository;
import com.zanol.scheduling.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public Optional<User> getUserByCode(String code) {
        return userRepository.findByCode(code);
    }

    @Override
    public Optional<User> createUser(User user) {
        return Optional.ofNullable(Objects.isNull(user.getId())
                ? userRepository.save(user)
                : null
        );
    }

    @Override
    public Optional<User> updateUser(Long id, User user) {
        Optional<User> userData = userRepository.findById(id);
        user.setId(id);

        return Optional.ofNullable(userData.isPresent()
                ? userRepository.save(user)
                : null
        );
    }

    @Override
    public boolean deleteUser(Long id) {
        boolean success = false;

        userRepository.deleteById(id);
        Optional<User> userData = userRepository.findById(id);

        if (userData.isPresent()) {
            userRepository.deleteById(id);
            success = true;
        }

        return success;
    }
}