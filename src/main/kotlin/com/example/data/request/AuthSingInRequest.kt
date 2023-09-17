package com.example.data.request

import kotlinx.serialization.Serializable

@Serializable
data class AuthSingInRequest(
    val identifier: String,
    val password: String
)
