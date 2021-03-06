package com.example.nosessionjwt

import com.example.nosessionjwt.entity.User
import com.example.nosessionjwt.repository.UserRepository
import com.example.nosessionjwt.security.EmailAndPasswordJsonRequest
import com.example.nosessionjwt.security.JWTProvider
import com.example.nosessionjwt.security.JWTProvider.Companion.X_AUTH_TOKEN
import com.example.nosessionjwt.security.LoginUser
import com.example.nosessionjwt.security.WebSecurityConfig.Companion.IS_AUTHENTICATED_FULLY
import com.example.nosessionjwt.security.WebSecurityConfig.Companion.ROLE_NORMAL
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.annotation.Secured
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import javax.servlet.http.HttpServletResponse


@SpringBootApplication
class Application

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}

@RestController
class Controller(
    private val userRepository: UserRepository,
    private val jwtProvider: JWTProvider,
    private val passwordEncoder: PasswordEncoder
) {
    @PostMapping(path = ["/api/signup"], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun signup(@RequestBody body: EmailAndPasswordJsonRequest, httpServletResponse: HttpServletResponse): String {
        val password = passwordEncoder.encode(body.password)
        val user = userRepository.save(User(email = body.email, password = password))
        val loginUser = LoginUser(user.id!!, user.roles.map { SimpleGrantedAuthority(it) })
        val authToken = jwtProvider.createToken(loginUser)
        httpServletResponse.setHeader(X_AUTH_TOKEN, authToken)
        // ???????????????????????????
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken(loginUser, null, loginUser.authorities)
        return """{ "id": ${user.id} }"""
    }

    @GetMapping("/api/non-personal")
    fun nonPersonal(@AuthenticationPrincipal loginUser: LoginUser?): String {
        return if (loginUser == null) {
            "everyone can see. not logged in."
        } else {
            "everyone can see. logged in."
        }
    }

    @Secured(IS_AUTHENTICATED_FULLY) // ?????????????????????????????????????????????
    @GetMapping("/api/personal/user")
    fun personalUser(@AuthenticationPrincipal loginUser: LoginUser): User =
        userRepository.findById(loginUser.id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND) }

    @PreAuthorize("hasRole('$ROLE_NORMAL')") // ??????????????????DB????????????????????????????????????????????????????????????????????????????????????
    @GetMapping(path = ["/api/personal/user"], params = ["role"])
    fun personalUserWithRole(@AuthenticationPrincipal loginUser: LoginUser): User =
        userRepository.findById(loginUser.id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND) }
}
