package com.zanol.scheduling.user.service;

import com.zanol.scheduling.user.model.User;

import java.util.List;
import java.util.Optional;

public interface UserService {

    List<User> getAllUsers();

    Optional<User> getUserById(Long id);

    Optional<User> getUserByCode(String code);

    Optional<User> createUser(User user);

    Optional<User> updateUser(Long id, User user);

    boolean deleteUser(Long id);
}