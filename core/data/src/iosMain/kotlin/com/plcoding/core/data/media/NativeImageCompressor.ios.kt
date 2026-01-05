@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.media

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.dataWithBytes
import platform.UIKit.UIImage
import platform.UIKit.UIImageJPEGRepresentation
import platform.UIKit.UIImagePNGRepresentation
import platform.posix.memcpy
import kotlin.math.roundToInt

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
        
        val image = UIImage(data = inputData)

        var outputBytes: ByteArray?

        if (file.mimeType == "image/png") {
            val pngData = UIImagePNGRepresentation(image)
            outputBytes = pngData?.toByteArray()
        } else {
            var currentQuality = quality
            var compressedData: NSData?

            do {
                ensureActive()
                compressedData = UIImageJPEGRepresentation(
                    image = image,
                    compressionQuality = currentQuality / 100.0
                )

                if (compressedData != null && compressedData.length.toLong() <= compressionThreshold) {
                    break
                }

                currentQuality -= (currentQuality * 0.1).roundToInt()
            } while (currentQuality > 5)

            outputBytes = compressedData?.toByteArray()
        }

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
