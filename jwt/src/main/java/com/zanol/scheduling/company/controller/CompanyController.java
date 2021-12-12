package com.zanol.scheduling.company.controller;

import com.zanol.scheduling.company.model.Company;
import com.zanol.scheduling.company.service.CompanyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/company")
public class CompanyController {

    @Autowired
    CompanyService companyService;

    @GetMapping("")
    public ResponseEntity<List<Company>> getAllCompanies(@RequestParam(required = false) String name, @RequestParam(required = false) String tin) {
        return new ResponseEntity<>(companyService.getAll(name, tin), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Company> getCompanyById(@PathVariable("id") Long id) {
        return companyService.getById(id).map(company -> new ResponseEntity<>(company, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PostMapping("")
    public ResponseEntity<Company> createCompany(@RequestBody Company company) {
        return companyService.create(company)
                .map(created -> new ResponseEntity<>(created, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.CONFLICT));
    }

    @PutMapping("/{id}")
    public ResponseEntity<Company> updateCompany(@PathVariable("id") Long id, @RequestBody Company company) {
        return companyService.update(id, company)
                .map(updated -> new ResponseEntity<>(updated, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }
}