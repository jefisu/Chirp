package com.plcoding.core.data.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import kotlin.math.roundToInt

actual class NativeImageCompressor : ImageCompressor {
    actual override suspend fun compressImage(
        file: File,
        compressionThreshold: Long,
        quality: Int
    ): ByteArray? {
        val compressFormat = when (file.mimeType) {
            "image/png" -> Bitmap.CompressFormat.PNG
            "image/jpeg" -> Bitmap.CompressFormat.JPEG
            "image/webp" -> if (Build.VERSION.SDK_INT >= 30) {
                Bitmap.CompressFormat.WEBP_LOSSLESS
            } else Bitmap.CompressFormat.WEBP

            else -> Bitmap.CompressFormat.JPEG
        }

        return try {
            val bitmap = BitmapFactory.decodeByteArray(file.bytes, 0, file.bytes.size)
            var outputBytes: ByteArray
            var currentQuality = quality

            withContext(Dispatchers.Default) {
                do {
                    ensureActive()
                    ByteArrayOutputStream().use { stream ->
                        bitmap.compress(compressFormat, currentQuality, stream)
                        outputBytes = stream.toByteArray()
                        currentQuality -= (currentQuality * 0.1).roundToInt()
                    }
                } while (
                    isActive &&
                    outputBytes.size > compressionThreshold &&
                    currentQuality > 5 &&
                    compressFormat != Bitmap.CompressFormat.PNG
                )
            }
            outputBytes
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()

            e.printStackTrace()
            null
        }
    }
}
