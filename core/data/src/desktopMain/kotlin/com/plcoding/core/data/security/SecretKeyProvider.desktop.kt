package com.plcoding.core.data.security

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

actual object SecretKeyProvider {

    private const val KEY_FILE_NAME = "chirp_crypto_key"

    actual fun getKey(): SecretKey {
        return loadKey() ?: createKey().apply { saveKey(this) }
    }

    private fun createKey(): SecretKey {
        return KeyGenerator.getInstance(Crypto.ALGORITHM)
            .apply {
                init(256)
            }
            .generateKey()
    }

    private fun getKeyFile(): File {
        val appDataDir = getAppDataDirectory()
        return File(appDataDir, KEY_FILE_NAME)
    }

    private fun getAppDataDirectory(): File {
        val os = System.getProperty("os.name").lowercase()
        val userHome = System.getProperty("user.home")

        val appDataPath = when {
            os.contains("win") -> {
                val appData = System.getenv("APPDATA") ?: "$userHome\\AppData\\Roaming"
                "$appData\\ChirpApp"
            }

            os.contains("mac") -> "$userHome/Library/Application Support/ChirpApp"
            else -> {
                val configHome = System.getenv("XDG_CONFIG_HOME") ?: "$userHome/.config"
                "$configHome/ChirpApp"
            }
        }

        return File(appDataPath).apply {
            if (!exists()) mkdirs()
        }
    }

    private fun saveKey(key: SecretKey) {
        runCatching {
            val keyFile = getKeyFile()
            val encodedKey = Base64.getEncoder().encodeToString(key.encoded)

            Files.write(
                keyFile.toPath(),
                encodedKey.toByteArray(),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING
            )

            // Set restrictive permissions (POSIX systems only)
            Files.setPosixFilePermissions(
                keyFile.toPath(),
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
                )
            )
        }.onFailure {
            throw RuntimeException("Failed to save encryption key: ${it.message}", it)
        }
    }

    private fun loadKey(): SecretKey? {
        return runCatching {
            val keyFile = getKeyFile()
            if (!keyFile.exists()) return null

            val encodedKey = String(Files.readAllBytes(keyFile.toPath()))
            val keyBytes = Base64.getDecoder().decode(encodedKey)
            SecretKeySpec(keyBytes, Crypto.ALGORITHM)
        }.getOrNull()
    }
}