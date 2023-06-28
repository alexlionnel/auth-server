package io.albrains.security.authserver.config.security

import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.util.StringUtils
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

class JWTFilter(private val tokenProvider: TokenProvider) : WebFilter {

    companion object {
        const val AUTHORIZATION_HEADER = "Authorization"
    }

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return resolveToken(exchange.request)?.let { jwt ->
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                val authentication: Authentication = tokenProvider.getAuthentication(jwt)
                return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
            }
            return chain.filter(exchange)
        } ?: chain.filter(exchange)
    }

    private fun resolveToken(request: ServerHttpRequest): String? {
        val bearerToken = request.headers.getFirst(AUTHORIZATION_HEADER)
        return if (StringUtils.hasText(bearerToken) && bearerToken!!.startsWith("Bearer ")) {
            bearerToken.substring(7)
        } else null
    }
}