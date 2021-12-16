package com.example.nosessionjwt.repository

import com.example.nosessionjwt.entity.User
import org.springframework.data.repository.CrudRepository
import java.util.*

interface UserRepository : CrudRepository<User, Int> {
    fun findByEmail(email: String): Optional<User>
}
