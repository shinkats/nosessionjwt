package com.example.nosessionjwt

import com.example.nosessionjwt.entity.User
import com.example.nosessionjwt.repository.UserRepository
import com.example.nosessionjwt.security.EmailAndPasswordJsonRequest
import com.example.nosessionjwt.security.JWTLoginUser
import com.example.nosessionjwt.security.JWTProvider
import com.example.nosessionjwt.security.JWTProvider.Companion.X_AUTH_TOKEN
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
        val jwtLoginUser = JWTLoginUser(user.id!!, user.roles)
        val authToken = jwtProvider.createToken(jwtLoginUser)
        httpServletResponse.setHeader(X_AUTH_TOKEN, authToken)
        // ログイン済とみなす
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken(jwtLoginUser, null, jwtLoginUser.authorities)
        return """{ "id": ${user.id} }"""
    }

    @GetMapping("/api/non-personal")
    fun nonPersonal(@AuthenticationPrincipal jwtLoginUser: JWTLoginUser?): String {
        return if (jwtLoginUser == null) {
            "everyone can see. not logged in."
        } else {
            "everyone can see. logged in."
        }
    }

    @Secured(IS_AUTHENTICATED_FULLY) // ログインしていればアクセス可能
    @GetMapping("/api/personal/user")
    fun personalUser(@AuthenticationPrincipal jwtLoginUser: JWTLoginUser): User =
        userRepository.findById(jwtLoginUser.id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND) }

    @PreAuthorize("hasRole('$ROLE_NORMAL')") // ログイン時にDBから取得した権限に指定のものが含まれていればアクセス可能
    @GetMapping(path = ["/api/personal/user"], params = ["role"])
    fun personalUserWithRole(@AuthenticationPrincipal jwtLoginUser: JWTLoginUser): User =
        userRepository.findById(jwtLoginUser.id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND) }
}
