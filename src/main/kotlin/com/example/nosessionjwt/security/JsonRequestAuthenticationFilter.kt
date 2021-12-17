package com.example.nosessionjwt.security

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class JsonRequestAuthenticationFilter(private val objectMapper: ObjectMapper) : UsernamePasswordAuthenticationFilter() {
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse?): Authentication {
        val principal = objectMapper.readValue(request.inputStream, EmailAndPasswordJsonRequest::class.java)
        val authRequest = UsernamePasswordAuthenticationToken(principal.email, principal.password)
        setDetails(request, authRequest)
        return authenticationManager.authenticate(authRequest)
    }
}
