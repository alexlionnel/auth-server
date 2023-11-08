package io.albrains.security.authserver.config.security

import io.albrains.security.authserver.service.UserApp
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SecurityException
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Component
class TokenProvider(
    @Value("classpath:certs/public.pem") private val publicKey: RSAPublicKey,
    @Value("classpath:certs/private.pem") private val privateKey: RSAPrivateKey
) {
    private val logger = KotlinLogging.logger{}

    private val jwtParser: JwtParser = Jwts.parserBuilder().setSigningKey(publicKey).build()

    companion object {
        private const val INVALID_JWT_TOKEN = "Invalid JWT token."
    }

    fun validateToken(jwt: String): Boolean {
        try {
            jwtParser.parseClaimsJws(jwt)
            return true
        } catch(e: ExpiredJwtException) {
            logger.trace(INVALID_JWT_TOKEN, e)
        } catch (e: UnsupportedJwtException) {
            logger.trace(INVALID_JWT_TOKEN, e)
        } catch (e: MalformedJwtException) {
            logger.trace(INVALID_JWT_TOKEN, e)
        } catch (e: SecurityException) {
            logger.trace(INVALID_JWT_TOKEN, e)
        } catch (e: IllegalArgumentException ) { // TODO: should we let it bubble (no catch), to avoid defensive programming and follow the fail-fast principle?
            logger.error("Token validation error ${e.message}", e)
        }

        return false
    }

    fun getAuthentication(jwt: String): Authentication {
        val claims = jwtParser.parseClaimsJws(jwt).body
        val principal = User(claims.subject, "", Collections.emptyList())
        val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(
            principal,
            jwt,
            Collections.emptyList()
        )

        usernamePasswordAuthenticationToken.details = claims

        return usernamePasswordAuthenticationToken
    }

    fun createToken(userApp: UserApp): String {

        return Jwts
            .builder()
            .setSubject(userApp.username)
            //.claim(TokenProvider.AUTHORITIES_KEY, Collections.emptyList<String>())
            .addClaims(mapOf())
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .setExpiration(tokenExpirationDate())
            .setIssuedAt(Date())
            //.serializeToJsonWith(JacksonSerializer<Any?>())
            .compact()
    }

    private fun tokenExpirationDate(): Date {
        val calendar = Calendar.getInstance()
        calendar.time = Date()
        calendar.add(Calendar.HOUR, 5)
        return calendar.time
    }
}