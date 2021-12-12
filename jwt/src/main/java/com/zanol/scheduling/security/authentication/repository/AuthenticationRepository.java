package com.zanol.scheduling.security.authentication.repository;

import com.zanol.scheduling.company.model.Company;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthenticationRepository extends JpaRepository<Company, Long> {
}