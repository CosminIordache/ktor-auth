package com.example

import com.example.data.request.AuthSingInRequest
import com.example.data.request.AuthSingUpRequest
import com.example.data.user.User
import com.example.data.user.UserDataSource
import com.example.security.hashing.HashingService
import com.example.security.hashing.SaltedHash
import com.example.security.token.TokenConfig
import com.example.security.token.TokenService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*


fun Route.user(
    userDataSource: UserDataSource
) {
    get("{username?}") {
        val username =
            call.parameters["username"] ?: return@get call.respond(HttpStatusCode.BadRequest, "Username not provided")
        val user = userDataSource.getUser(username)
        if (user != null) {
            call.respond(HttpStatusCode.OK, "$user")
        } else {
            call.respond(HttpStatusCode.NotFound, "User not found")
        }
    }
}

fun Route.signUp(
    hashingService: HashingService,
    userDataSource: UserDataSource
) {
    post("/signup") {
        val request = kotlin.runCatching { call.receiveNullable<AuthSingUpRequest>() }.getOrNull() ?: kotlin.run {
            call.respond(HttpStatusCode.BadRequest)
            return@post
        }

        //Credentials
        val areFieldsBlank = request.username.isBlank() || request.email.isBlank() || request.password.isBlank()
        val isPwShort = request.password.length < 6
        val invalidCharactersRegex = """[@!%#()=+\-\\/.,"]""".toRegex()
        val usernameBadCredentials = invalidCharactersRegex.containsMatchIn(request.username)
        val existingUserByUsername = userDataSource.getUser(request.username)
        val existingUserByEmail = userDataSource.getUserByEmail(request.email)

        //algun field esta no esta completado o la contraseña es demasiado corta
        if (areFieldsBlank || isPwShort) {
            call.respond(HttpStatusCode.Conflict)
            return@post
        }

        //username bad credentials
        if (usernameBadCredentials) {
            call.respond(HttpStatusCode.Conflict, "Username contains invalid characters")
            return@post
        }

        //username ya existe
        if (existingUserByUsername != null) {
            call.respond(HttpStatusCode.Conflict, "Username already exists")
            return@post
        }

        //email ya existe
        if (existingUserByEmail != null) {
            call.respond(HttpStatusCode.Conflict, "Email already exists")
            return@post
        }

        val saltedHash = hashingService.generateSaltedHash(request.password)
        val user = User(
            username = request.username,
            email = request.email,
            password = saltedHash.hash,
            salt = saltedHash.salt
        )

        //Si usuario existe
        val wasAcknownledged = userDataSource.insertNewUser(user)
        if (!wasAcknownledged) {
            call.respond(HttpStatusCode.Conflict)
            return@post
        }

        call.respond(HttpStatusCode.OK)

    }
}

fun Route.signIn(
    hashingService: HashingService,
    userDataSource: UserDataSource,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    post("/signin") {
        val request = kotlin.runCatching { call.receiveNullable<AuthSingInRequest>() }.getOrNull() ?: kotlin.run {
            call.respond(HttpStatusCode.BadRequest, "Invalid format")
            return@post
        }

        val user = if (request.identifier.contains('@')) {
            // Si identifier contiene '@', asumimos que es un correo electrónico
            userDataSource.getUserByEmail(request.identifier)
        } else {
            // Sino, asumimos que es un nombre de usuario
            userDataSource.getUser(request.identifier)
        }

        if (user == null) {
            val errorMessage = if (request.identifier.contains('@')) {
                "Incorrect email"
            } else {
                "Incorrect username"
            }
            call.respond(HttpStatusCode.Conflict, errorMessage)
            return@post
        }

        val isValidPassword = hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash = user.password,
                salt = user.salt
            )
        )

        if (!isValidPassword) {
            call.respond(HttpStatusCode.Conflict, "Incorrect password")
        }

//        val token = tokenService.generate(
//            config = tokenConfig,
//            TokenClaim(
//                name = "userId",
//                value = user.id.toString()
//            )
//        )

        call.respond(
            status = HttpStatusCode.OK,
            message = "SignIn \n $user"
        )

    }
}

fun Route.authenticate() {
    authenticate {
        get("/authenticate") {
            call.respond(HttpStatusCode.OK)
        }
    }
}


//Obtienes el id del usuario si esta authenticado mediante el token
fun Route.getSecretInfo() {
    authenticate {
        get("/secret") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.getClaim("userId", String::class)
            call.respond(HttpStatusCode.OK, " Your userId is $userId")
        }
    }
}