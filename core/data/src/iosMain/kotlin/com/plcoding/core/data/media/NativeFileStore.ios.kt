@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.media

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.FileStore
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDomainMask
import platform.Foundation.dataWithBytes
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.writeToFile
import platform.posix.memcpy

actual class NativeFileStore(
    private val logger: ChirpLogger
) : FileStore {

    actual override suspend fun saveFile(bytes: ByteArray, fileName: String): String? {
        return withContext(Dispatchers.Default) {
            val fullPath = getFilePath(fileName)
            val data = bytes.toNSData()
            runCatching {
                data.writeToFile(fullPath, true)
                fullPath
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to save file: $fileName", e)
                e.printStackTrace()
            }.getOrNull()
        }
    }

    actual override fun getFilePath(fileName: String): String {
        val documentDirectory = NSFileManager.defaultManager.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = true,
            error = null
        )
        return requireNotNull(documentDirectory?.path) + "/" + fileName
    }

    actual override suspend fun getFile(filePath: String): ByteArray? {
        return withContext(Dispatchers.Default) {
            runCatching {
                val data = NSData.dataWithContentsOfFile(filePath)
                data?.toByteArray()
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to read file: $filePath", e)
                e.printStackTrace()
            }.getOrNull()
        }
    }

    actual override suspend fun deleteFile(filePath: String) {
        withContext(Dispatchers.Default) {
            runCatching {
                NSFileManager.defaultManager.removeItemAtPath(filePath, null)
            }.onFailure { e ->
                coroutineContext.ensureActive()
                logger.error("Failed to delete file: $filePath", e)
                e.printStackTrace()
            }
        }
    }

    private fun ByteArray.toNSData(): NSData {
        if (isEmpty()) return NSData.dataWithBytes(null, 0u)
        return usePinned {
            NSData.dataWithBytes(it.addressOf(0), size.toULong())
        }
    }

    private fun NSData.toByteArray(): ByteArray {
        val size = length.toInt()
        if (size == 0) return ByteArray(0)
        return ByteArray(size).apply {
            usePinned {
                memcpy(it.addressOf(0), bytes, length)
            }
        }
    }
}
