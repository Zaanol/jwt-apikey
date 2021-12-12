package com.zanol.scheduling.company.service;

import com.zanol.scheduling.company.model.Company;

import java.util.List;
import java.util.Optional;

public interface CompanyService {

    List<Company> getAll(String name, String tin);

    Optional<Company> getById(Long id);

    Optional<Company> create(Company company);

    Optional<Company> update(Long id, Company company);

    boolean delete(Long id);
}