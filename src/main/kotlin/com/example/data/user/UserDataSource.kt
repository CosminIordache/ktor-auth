package com.example.data.user

import com.mongodb.kotlin.client.MongoCollection
import com.mongodb.kotlin.client.MongoDatabase

interface UserDataSource {
    suspend fun getUser(username: String) : User?
    suspend fun getUserByEmail(email: String) : User?
    suspend fun insertNewUser(user: User) : Boolean
}