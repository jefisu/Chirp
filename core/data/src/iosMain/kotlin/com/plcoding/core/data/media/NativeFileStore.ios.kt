@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package com.plcoding.core.data.media

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.media.StorageDestination
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSString
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.stringByAppendingPathComponent
import platform.Foundation.writeToFile
import platform.UIKit.UIImage
import platform.UIKit.UIImageWriteToSavedPhotosAlbum
import platform.posix.memcpy

actual class NativeFileStore(
    private val logger: ChirpLogger
) : FileStore {

    actual override suspend fun saveFile(
        bytes: ByteArray,
        fileName: String,
        destination: StorageDestination
    ): String? {
        return withContext(Dispatchers.Default) {
            runCatching {
                when (destination) {
                    StorageDestination.GALLERY -> {
                        saveToGallery(bytes)
                        null
                    }

                    else -> saveToInternalStorage(fileName, bytes)
                }
            }.onFailure {
                coroutineContext.ensureActive()
                logger.error("Failed to write to file: $fileName", it)
            }.getOrNull()
        }
    }

    @Suppress("CAST_NEVER_SUCCEEDS")
    actual override fun getFilePath(fileName: String): String {
        val paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, true)
        val directory = paths.firstOrNull() as? String ?: ""
        return (directory as NSString).stringByAppendingPathComponent(fileName)
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

    private fun saveToInternalStorage(
        fileName: String,
        bytes: ByteArray
    ): String {
        val fullPath = getFilePath(fileName)
        val data = bytes.toNSData()
        data.writeToFile(fullPath, true)
        return fullPath
    }

    private fun saveToGallery(bytes: ByteArray) {
        val nsData = bytes.toNSData()
        val uiImage = UIImage(nsData)
        UIImageWriteToSavedPhotosAlbum(uiImage, null, null, null)
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

    private fun ByteArray.toNSData(): NSData {
        return usePinned {
            NSData.create(
                bytes = it.addressOf(0),
                length = size.toULong(),
            )
        }
    }
}
