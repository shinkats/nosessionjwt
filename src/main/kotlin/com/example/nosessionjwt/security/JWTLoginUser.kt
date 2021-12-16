package com.example.nosessionjwt.security

import org.springframework.security.core.authority.SimpleGrantedAuthority

class JWTLoginUser(val id: Int, roles: List<String>) {
    val authorities = roles.map { SimpleGrantedAuthority(it) }
}
