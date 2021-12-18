package com.example.nosessionjwt.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.servlet.ServletRequest
import javax.servlet.http.HttpServletRequest

@Component
class JWTProvider(@Value("${'$'}{jwt.secret}") secret: String) {

    val algorithm: Algorithm = Algorithm.HMAC256(secret)

    fun createToken(user: LoginUser): String {
        val now = Date()
        return JWT.create()
            .withIssuer("com.example.nosessionjwt")
            .withIssuedAt(now)
            .withExpiresAt(Date(now.time + 1000 * 60 * 60))
            .withSubject(user.id.toString())
            .withClaim(CLAIM_ROLES, user.authorities.map { it.authority })
            .sign(algorithm)
    }


    fun getToken(request: ServletRequest): String? {
        val token: String? = (request as HttpServletRequest).getHeader(X_AUTH_TOKEN)
        return token?.takeIf { it.startsWith("Bearer ") }?.substring(7)
    }

    fun verifyToken(token: String): DecodedJWT {
        val verifier = JWT.require(algorithm).build()
        return verifier.verify(token)
    }

    fun retrieve(decodedJWT: DecodedJWT): LoginUser {
        val userId = decodedJWT.subject.toInt()
        val roles = decodedJWT.getClaim(CLAIM_ROLES).asList(String::class.java)
        return LoginUser(userId, roles)
    }

    companion object {
        const val X_AUTH_TOKEN = "X-AUTH-TOKEN"
        const val CLAIM_ROLES = "roles"
    }
}
