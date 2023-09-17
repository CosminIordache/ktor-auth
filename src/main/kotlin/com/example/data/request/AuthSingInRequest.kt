package com.example.data.request

import kotlinx.serialization.Serializable

@Serializable
data class AuthSingInRequest(
    val email: String,
    val password: String
)
