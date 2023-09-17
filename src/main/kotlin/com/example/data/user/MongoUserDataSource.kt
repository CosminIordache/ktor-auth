package com.example.data.user

import com.mongodb.client.model.Filters
import com.mongodb.kotlin.client.MongoDatabase


class MongoUserDataSource(
    db: MongoDatabase
): UserDataSource {

    private val users = db.getCollection<User>("users")

    override suspend fun getUser(username: String): User? {
        val filter = Filters.eq("username", username)
        return users.find(filter).limit(1).firstOrNull()
    }

    override suspend fun getUserByEmail(email: String): User? {
        val filter = Filters.eq("email", email)
        return users.find(filter).limit(1).firstOrNull()
    }

    override suspend fun insertNewUser(user: User): Boolean {
        return users.insertOne(user).wasAcknowledged()
    }
}