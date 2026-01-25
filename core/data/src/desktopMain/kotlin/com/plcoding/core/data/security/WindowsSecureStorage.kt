package com.plcoding.core.data.security

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

internal class WindowsSecureStorage(
    private val logger: ChirpLogger
) : SecureStorage {

    private val storageDir = File(System.getProperty("user.home"), ".chirp/secure")
    private val storageFile = File(storageDir, "credentials.dat")
    private val keyFile = File(storageDir, "key.dat")

    private val secretKey: SecretKeySpec by lazy {
        try {
            if (keyFile.exists()) {
                val keyData = Base64.getDecoder().decode(keyFile.readText())
                SecretKeySpec(keyData, "AES")
            } else {
                storageDir.mkdirs()
                val password = generateRandomPassword()
                val salt = generateSalt()
                val key = deriveKey(password, salt)
                keyFile.writeText(Base64.getEncoder().encodeToString(key.encoded))
                key
            }
        } catch (e: Exception) {
            logger.error("Failed to initialize encryption key", e)
            throw e
        }
    }

    init {
        storageDir.mkdirs()
    }

    override suspend fun saveString(key: String, value: String) {
        withContext(Dispatchers.IO) {
            try {
                val data = loadData().toMutableMap()
                val encryptedValue = encrypt(value)
                data[key] = encryptedValue
                saveData(data)
            } catch (e: Exception) {
                logger.error("Failed to save encrypted data for key: $key", e)
            }
        }
    }

    override suspend fun getString(key: String): String? = withContext(Dispatchers.IO) {
        try {
            val data = loadData()
            data[key]?.let { decrypt(it) }
        } catch (e: Exception) {
            logger.error("Failed to retrieve encrypted data for key: $key", e)
            null
        }
    }

    override suspend fun remove(key: String) {
        withContext(Dispatchers.IO) {
            try {
                val data = loadData().toMutableMap()
                data.remove(key)
                saveData(data)
            } catch (e: Exception) {
                logger.error("Failed to remove data for key: $key", e)
            }
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) {
            try {
                if (storageFile.exists()) {
                    storageFile.delete()
                }
            } catch (e: Exception) {
                logger.error("Failed to clear secure storage", e)
            }
        }
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val combined = iv + encrypted
        return Base64.getEncoder().encodeToString(combined)
    }

    private fun decrypt(encryptedValue: String): String? {
        return try {
            val combined = Base64.getDecoder().decode(encryptedValue)
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            val encrypted = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
            val decrypted = cipher.doFinal(encrypted)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            logger.error("Failed to decrypt data", e)
            null
        }
    }

    private fun generateRandomPassword(): CharArray {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes).toCharArray()
    }

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password, salt, 65536, 256)
        val secret = factory.generateSecret(spec)
        return SecretKeySpec(secret.encoded, "AES")
    }

    private fun loadData(): Map<String, String> {
        if (!storageFile.exists()) return emptyMap()
        return try {
            storageFile.readLines()
                .filter { it.contains("=") }
                .associate { line ->
                    val (key, value) = line.split("=", limit = 2)
                    key to value
                }
        } catch (e: Exception) {
            logger.error("Failed to load data from storage file", e)
            emptyMap()
        }
    }

    private fun saveData(data: Map<String, String>) {
        val content = data.entries.joinToString("\n") { "${it.key}=${it.value}" }
        storageFile.writeText(content)
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
