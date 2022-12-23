package com.jwctech.jwtdemo.entity;

import javax.persistence.*;

@Entity
public class InvalidToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(length = 65555)
    private String revokedToken;

    public InvalidToken(Long id, String revokedToken) {
        this.id = id;
        this.revokedToken = revokedToken;
    }

    public InvalidToken(){
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRevokedToken() {
        return revokedToken;
    }

    public void setRevokedToken(String revokedToken) {
        this.revokedToken = revokedToken;
    }

}
