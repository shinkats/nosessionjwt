package com.example.nosessionjwt.security

import com.example.nosessionjwt.repository.UserRepository
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.password.PasswordEncoder


@Configuration
class JsonRequestAuthenticationProvider(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val email = authentication.principal as String
        val password = authentication.credentials as String
        val user = userRepository.findByEmail(email).orElseThrow { BadCredentialsException("no user") }
        if (!passwordEncoder.matches(password, user.password)) {
            throw BadCredentialsException("incorrect password")
        }
        val loginUser = LoginUser(user.id!!, user.roles.map { SimpleGrantedAuthority(it) })
        return UsernamePasswordAuthenticationToken(loginUser, null, loginUser.authorities)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
