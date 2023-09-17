package com.example.data.request

import kotlinx.serialization.Serializable

@Serializable
data class AuthSingUpRequest(
    val username: String,
    val email: String,
    val password: String
)
