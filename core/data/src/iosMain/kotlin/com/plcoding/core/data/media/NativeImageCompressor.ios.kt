@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.media

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import com.plcoding.core.domain.media.resize
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.useContents
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.dataWithBytes
import platform.UIKit.UIImage
import platform.UIKit.UIImageJPEGRepresentation
import platform.UIKit.UIImagePNGRepresentation
import platform.posix.memcpy

actual class NativeImageCompressor : ImageCompressor {

    actual override suspend fun compressImage(
        file: File,
        compressionThreshold: Long,
        quality: Int
    ): ByteArray? = withContext(Dispatchers.Default) {
        val inputData = if (file.bytes.isNotEmpty()) {
            file.bytes.toNSData()
        } else {
            return@withContext null
        }

        var image = UIImage(data = inputData)
        val isPng = file.mimeType == "image/png"

        var currentQuality = quality
        var outputBytes: ByteArray?
        var attempt = 0
        val maxAttempts = 15

        do {
            ensureActive()
            attempt++

            val compressedData: NSData? = if (isPng) {
                UIImagePNGRepresentation(image)
            } else {
                UIImageJPEGRepresentation(image, currentQuality / 100.0)
            }

            outputBytes = compressedData?.toByteArray()
            val size = outputBytes?.size ?: 0

            if (size <= compressionThreshold) {
                return@withContext outputBytes
            }

            if (attempt >= maxAttempts) {
                return@withContext outputBytes
            }

            val shouldDownscale = isPng || currentQuality < 20

            if (shouldDownscale) {
                val scaleFactor = 0.75
                val newWidth = image.size.useContents { width } * scaleFactor
                val newHeight = image.size.useContents { height } * scaleFactor

                if (newWidth < 200 || newHeight < 200) {
                    return@withContext outputBytes
                }

                image = image.resize(newWidth, newHeight)

                if (!isPng) {
                    currentQuality = (quality * 0.8).toInt().coerceAtLeast(50)
                }
            } else {
                currentQuality = (currentQuality * 0.8).toInt()
            }

        } while (isActive)

        outputBytes
    }

    private fun ByteArray.toNSData(): NSData {
        if (isEmpty()) return NSData.dataWithBytes(null, 0u)
        return usePinned {
            NSData.dataWithBytes(it.addressOf(0), size.toULong())
        }
    }

    private fun NSData.toByteArray(): ByteArray {
        val size = this.length.toInt()
        if (size == 0) return ByteArray(0)
        return ByteArray(size).apply {
            usePinned {
                memcpy(it.addressOf(0), bytes, length)
            }
        }
    }
}
