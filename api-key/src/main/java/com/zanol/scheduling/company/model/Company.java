package com.zanol.scheduling.company.model;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Entity
public class Company {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;

    private String name;

    @Column(unique=true)
    @NotBlank(message = "Cnpj can't be blank")
    private String tin;

    private Boolean active;

    public Company() {
    }

    public Company(String name, String tin) {
        this.name = name;
        this.tin = tin;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTin() {
        return tin;
    }

    public void setTin(String cnpj) {
        this.tin = cnpj;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}