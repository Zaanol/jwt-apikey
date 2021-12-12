package com.zanol.scheduling.security.authentication.model;

public class AuthRequest {

    private String code;
    private String password;

    public AuthRequest() {
    }

    public AuthRequest(String code, String password) {
        this.code = code;
        this.password = password;
    }

    public String getCode() {
        if (this.code == null)
            this.code = "";

        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getPassword() {
        if (this.password == null)
            this.password = "";

        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}