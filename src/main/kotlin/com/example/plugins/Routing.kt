package com.example.plugins

import com.example.*
import com.example.data.user.MongoUserDataSource
import com.example.data.user.UserDataSource
import com.example.security.hashing.HashingService
import com.example.security.token.TokenConfig
import com.example.security.token.TokenService
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    routing {
        user(
            userDataSource = userDataSource
        )
        signIn(
            userDataSource = userDataSource,
            hashingService = hashingService,
            tokenConfig = tokenConfig,
            tokenService = tokenService
        )
        signUp(
            hashingService = hashingService,
            userDataSource = userDataSource
        )
        authenticate()
        getSecretInfo()
    }
}
