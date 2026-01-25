package com.plcoding.core.data.security

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage
import com.plcoding.core.domain.security.SecureStorageKeys.AUTH_INFO
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

internal class LinuxSecureStorage(
    private val logger: ChirpLogger
) : SecureStorage {

    private val serviceName = "com.plcoding.chirp"

    override suspend fun saveString(key: String, value: String) {
        withContext(Dispatchers.IO) {
            try {
                val process = ProcessBuilder(
                    "secret-tool",
                    "store",
                    "--label=$serviceName $key",
                    "service", serviceName,
                    "account", key
                ).start()

                process.outputStream.bufferedWriter().use { writer ->
                    writer.write(value)
                }

                val exitCode = process.waitFor()
                if (exitCode != 0) {
                    logger.error("Failed to save to Linux Secret Service for key: $key, exit code: $exitCode")
                }
            } catch (e: Exception) {
                logger.error("Failed to save encrypted data for key: $key", e)
            }
        }
    }

    override suspend fun getString(key: String): String? = withContext(Dispatchers.IO) {
        try {
            val process = ProcessBuilder(
                "secret-tool",
                "lookup",
                "service", serviceName,
                "account", key
            ).redirectErrorStream(false)
                .start()

            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readText()
            process.waitFor()

            if (process.exitValue() == 0 && result.isNotEmpty()) result else null
        } catch (e: Exception) {
            logger.error("Failed to retrieve encrypted data for key: $key", e)
            null
        }
    }

    override suspend fun remove(key: String) {
        withContext(Dispatchers.IO) {
            try {
                deleteItem(key)
            } catch (e: Exception) {
                logger.error("Failed to remove data for key: $key", e)
            }
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) {
            try {
                deleteItem(AUTH_INFO)
            } catch (e: Exception) {
                logger.error("Failed to clear secure storage", e)
            }
        }
    }

    private fun deleteItem(key: String) {
        try {
            val process = ProcessBuilder(
                "secret-tool",
                "clear",
                "service", serviceName,
                "account", key
            ).start()

            process.waitFor()
        } catch (_: Exception) {
            // Item might not exist, which is fine
        }
    }
}
