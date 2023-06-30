package io.albrains.security.authserver.service

import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class UserService {
    fun findByUsernameAndPassword(username: String, password: String): Mono<UserApp> {
        return Mono.just(UserApp("user", "pass"))
            .switchIfEmpty(Mono.error(Exception("Username or password not found")))
    }
}