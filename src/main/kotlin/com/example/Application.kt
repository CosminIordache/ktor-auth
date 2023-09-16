package com.example

import com.example.data.user.MongoUserDataSource
import com.example.plugins.*
import com.example.security.hashing.SHA256HashingService
import com.example.security.token.JwtTokenService
import com.example.security.token.TokenConfig
import com.mongodb.kotlin.client.MongoClient
import io.ktor.server.application.*

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {

    val mongoPw = "cosmin-ktor_auth"
    val dbName = "ktor-auth"
    val db = MongoClient.create(
        connectionString = "mongodb+srv://CosminIordache:$mongoPw@cluster0.phvvraw.mongodb.net/$dbName?retryWrites=true&w=majority"
    ).getDatabase(dbName)

    val userDataSource = MongoUserDataSource(db)
    val tokenService = JwtTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").toString(),
        audience = environment.config.property("jwt.audience").toString(),
        expiresIn = 365L * 1000L * 60L * 60L * 24L,
        secret = "jwt_secret"
    )
    val hashingService = SHA256HashingService()

    configureSecurity(tokenConfig)
    configureMonitoring()
    configureSerialization()
    configureRouting(userDataSource, hashingService, tokenService, tokenConfig)
}
