package io.albrains.security.authserver.controller

import io.albrains.security.authserver.config.security.TokenProvider
import io.albrains.security.authserver.controller.dto.AuthRequest
import io.albrains.security.authserver.controller.dto.AuthResponse
import io.albrains.security.authserver.service.UserService
import org.springframework.http.MediaType
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

@Component
class AuthHandler(private val passwordEncoder: PasswordEncoder,
                  private val tokenProvider: TokenProvider,
                  private val userService: UserService) {

    fun authenticate(request: ServerRequest): Mono<ServerResponse> {
        return request.bodyToMono(AuthRequest::class.java)
            .flatMap { userService.findByUsernameAndPassword(it.username, passwordEncoder.encode(it.password)) }
            .flatMap { ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(AuthResponse(tokenProvider.createToken(it)), AuthResponse::class.java)
            }
    }
}