package com.example.nosessionjwt.security

import org.springframework.security.core.authority.SimpleGrantedAuthority

class LoginUser(val id: Int, roles: List<String>) {
    val authorities = roles.map { SimpleGrantedAuthority(it) }
}
