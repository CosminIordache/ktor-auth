package com.example.data.user

interface UserDataSource {
    suspend fun getUserByEmail(email: String) : User?
    suspend fun insertNewUser(user: User) : Boolean
}