package io.albrains.security.authserver.controller

import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

@Component
class HelloHandler {

    fun hello(request: ServerRequest): Mono<ServerResponse> {
        return ServerResponse.ok().body("Hello world", String::class.java)
    }
}