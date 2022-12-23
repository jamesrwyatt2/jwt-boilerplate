package com.jwctech.jwtdemo.entity;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    /* ToDo: add roles */

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();


    private boolean enabled = true;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        this.enabled = true;
        this.roles = new HashSet<>();
    }

    public User() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> authorities) {
        this.roles = authorities;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    @Override
    public String toString(){

        String roleString = this.roles.stream()
                .map(n -> String.valueOf(n.getAuthority()))
                .collect(Collectors.joining("-"));

        return "username: " + this.username +
                ", enabled: " + this.enabled +
                ", roles: " + roleString;
    }
}

