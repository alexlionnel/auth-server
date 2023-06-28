package io.albrains.security.authserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SecureServerApplication

fun main(args: Array<String>) {
    runApplication<SecureServerApplication>(*args)
}
