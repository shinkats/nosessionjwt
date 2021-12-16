package com.example.nosessionjwt.security

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse


class JWTTokenFilter(private val jwtProvider: JWTProvider) : GenericFilterBean() {
    override fun doFilter(request: ServletRequest, response: ServletResponse?, chain: FilterChain) {
        val token: String? = jwtProvider.getToken(request)
        if (token != null) {
            val decodedJWT = jwtProvider.verifyToken(token)
            val jwtLoginUser = jwtProvider.retrieve(decodedJWT)
            SecurityContextHolder.getContext().authentication =
                UsernamePasswordAuthenticationToken(jwtLoginUser, null, jwtLoginUser.authorities)
        }
        chain.doFilter(request, response)
    }
}
