package com.zanol.scheduling.company.service.impl;

import com.zanol.scheduling.company.model.Company;
import com.zanol.scheduling.company.repository.CompanyRepository;
import com.zanol.scheduling.company.repository.CompanySpecification;
import com.zanol.scheduling.company.service.CompanyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
public class CompanyServiceImpl implements CompanyService {

    @Autowired
    CompanyRepository companyRepository;

    @Override
    public List<Company> getAll(String name, String tin) {
        Specification<Company> specification = null;

        if (!Objects.isNull(name) && !Objects.isNull(tin)) {
            specification = Specification
                    .where(CompanySpecification.nameLike(name))
                    .and(CompanySpecification.tinEqual(tin));
        } else if (!Objects.isNull(name)) {
            specification = CompanySpecification.nameLike(name);
        } else if (!Objects.isNull(tin)) {
            specification = CompanySpecification.tinEqual(tin);
        }

        return companyRepository.findAll(specification);
    }

    @Override
    public Optional<Company> getById(Long id) {
        return companyRepository.findById(id);
    }

    @Override
    public Optional<Company> create(Company company) {
        return Optional.ofNullable(Objects.isNull(company.getId())
                ? companyRepository.save(company)
                : null
        );
    }

    @Override
    public Optional<Company> update(Long id, Company company) {
        Optional<Company> companyData = companyRepository.findById(id);

        if (companyData.isPresent()) {
            Company companyFromDb = companyData.get();

            return Optional.of(companyRepository.save(companyFromDb));
        } else {
            return null;
        }
    }

    @Override
    public boolean delete(Long id) {
        boolean success = false;

        Optional<Company> CompanyData = companyRepository.findById(id);

        if (CompanyData.isPresent()) {
            companyRepository.deleteById(id);
            success = true;
        }

        return success;
    }
}