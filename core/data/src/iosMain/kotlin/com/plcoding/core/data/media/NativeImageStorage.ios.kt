@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.media

import com.plcoding.core.domain.media.ImageStorage
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.dataWithBytes
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.temporaryDirectory
import platform.Foundation.writeToFile
import platform.posix.memcpy
import kotlin.time.Clock

actual class NativeImageStorage : ImageStorage {
    actual override suspend fun saveImage(bytes: ByteArray, fileName: String?): String? {
        return withContext(Dispatchers.Default) {
            val name = fileName ?: ("image_${Clock.System.now()}.jpg")
            val fullPath = NSFileManager.defaultManager.temporaryDirectory.path + "/" + name
            val data = bytes.toNSData()
            data.writeToFile(fullPath, true)
            fullPath
        }
    }

    actual override suspend fun getImage(filePath: String): ByteArray? {
        return withContext(Dispatchers.Default) {
            val data = NSData.dataWithContentsOfFile(filePath)
            data?.toByteArray()
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