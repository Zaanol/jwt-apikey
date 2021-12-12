package com.zanol.scheduling.user.repository;

import com.zanol.scheduling.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByCode(String code);
}