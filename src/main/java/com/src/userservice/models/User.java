package com.src.userservice.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
public class User extends BaseModel {
    private String email;
    private String password;
    @ManyToMany(fetch = jakarta.persistence.FetchType.EAGER)
    private Set<Role> roles = new java.util.LinkedHashSet<>();
}