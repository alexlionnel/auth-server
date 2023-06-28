package io.albrains.security.authserver.controller

import io.albrains.security.authserver.config.security.TokenProvider
import io.albrains.security.authserver.controller.dto.AuthRequest
import io.albrains.security.authserver.controller.dto.AuthResponse
import io.albrains.security.authserver.service.UserService
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/api/authenticate")
class AuthController(private val passwordEncoder: PasswordEncoder,
                     private val tokenProvider: TokenProvider,
                     private val userService: UserService) {

    @PostMapping
    fun authenticate(@RequestBody authRequest: AuthRequest): Mono<ResponseEntity<AuthResponse>> {
        return userService.findByUsernameAndPassword(authRequest.username, passwordEncoder.encode(authRequest.password))
            .map { ResponseEntity.ok(AuthResponse(tokenProvider.createToken(it))) }
    }
}