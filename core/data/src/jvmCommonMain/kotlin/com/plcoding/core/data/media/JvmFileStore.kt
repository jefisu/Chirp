package com.plcoding.core.data.media

import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File

class JvmFileStore(
    private val logger: ChirpLogger
) {

    suspend fun saveFile(
        bytes: ByteArray,
        directory: File,
        fileName: String,
    ): String? {
        return withContext(Dispatchers.IO) {
            runCatching {
                if (!directory.exists()) {
                    directory.mkdirs()
                }

                File(directory, fileName)
                    .apply { writeBytes(bytes) }
                    .absolutePath
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to save file: $fileName", e)
                e.printStackTrace()
            }.getOrNull()
        }
    }

    suspend fun getFile(filePath: String): ByteArray? {
        return withContext(Dispatchers.IO) {
            val file = File(filePath)
            runCatching {
                file.readBytes()
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to read file: $filePath", e)
                e.printStackTrace()
            }.getOrNull()
        }
    }

    suspend fun deleteFile(filePath: String) {
        withContext(Dispatchers.IO) {
            runCatching {
                File(filePath).delete()
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to delete file: $filePath", e)
                e.printStackTrace()
            }
        }
    }
}
