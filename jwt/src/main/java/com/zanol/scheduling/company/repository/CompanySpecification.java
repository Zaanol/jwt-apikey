package com.zanol.scheduling.company.repository;

import com.zanol.scheduling.company.model.Company;
import org.springframework.data.jpa.domain.Specification;

public class CompanySpecification {

    public static Specification<Company> nameLike(String name) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.like(root.get("name"), "%" + name + "%");
    }

    public static Specification<Company> tinEqual(String tin) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.equal(root.get("tin"), tin);
    }
}