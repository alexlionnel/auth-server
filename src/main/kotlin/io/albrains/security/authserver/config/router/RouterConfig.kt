package io.albrains.security.authserver.config.router

import io.albrains.security.authserver.controller.AuthHandler
import io.albrains.security.authserver.controller.HelloHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.router

@Configuration
class RouterConfig {

    @Bean
    fun root(authHandler: AuthHandler, helloHandler: HelloHandler): RouterFunction<ServerResponse> {
        return router {
            (accept(MediaType.APPLICATION_JSON) and "/api").nest{
                POST("/authenticate", authHandler::authenticate)

            }
            GET("/hello", helloHandler::hello)
        }
    }
}