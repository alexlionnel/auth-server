package io.albrains.security.authserver.config.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache
import reactor.core.publisher.Mono

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SecurityConfig(private val tokenProvider: TokenProvider) {

    companion object {
        const val contentSecurityPolicy =
            "default-src 'self'; frame-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://storage.googleapis.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:"
    }

    @Bean
    fun securityFilterChain(http: ServerHttpSecurity, serverCodecConfigurer: ServerCodecConfigurer): SecurityWebFilterChain {
        return http
            .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint{swe, e -> Mono.fromRunnable{
                    swe.response.setStatusCode(HttpStatus.UNAUTHORIZED);
                }}
                .accessDeniedHandler{swe, e -> Mono.fromRunnable{
                    swe.response.setStatusCode(HttpStatus.FORBIDDEN);
                }}
            .and()
                .authorizeExchange()
                .pathMatchers("/api/authenticate").permitAll()
                .pathMatchers("/management/health").permitAll()
                .pathMatchers("/management/health/**").permitAll()
                .pathMatchers("/management/info").permitAll()
                .pathMatchers("/management/prometheus").permitAll()
                .pathMatchers("/management/**").hasAuthority(Role.ROLE_ADMIN.name)
                .anyExchange().authenticated()
            .and()
                .requestCache()
                .requestCache(NoOpServerRequestCache.getInstance())
            .and()
                .headers()
                .contentSecurityPolicy(contentSecurityPolicy)
                .and()
                    .referrerPolicy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                    .permissionsPolicy().policy("camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()")
                .and()
                    .frameOptions().disable()
            .and()
                .addFilterAt(JWTFilter(tokenProvider), SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
    }

    @Bean
    fun passwordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
}