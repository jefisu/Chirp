package com.plcoding.core.data.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import androidx.core.graphics.scale
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import kotlinx.coroutines.Dispatchers
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
        return withContext(Dispatchers.Default) {
            val compressFormat = when (file.mimeType) {
                "image/png" -> Bitmap.CompressFormat.PNG
                "image/jpeg" -> Bitmap.CompressFormat.JPEG
                "image/webp" -> if (Build.VERSION.SDK_INT >= 30) {
                    Bitmap.CompressFormat.WEBP_LOSSLESS
                } else Bitmap.CompressFormat.WEBP

                else -> Bitmap.CompressFormat.JPEG
            }

            val isLossless = compressFormat == Bitmap.CompressFormat.PNG ||
                    (Build.VERSION.SDK_INT >= 30 && compressFormat == Bitmap.CompressFormat.WEBP_LOSSLESS)

            try {
                var bitmap = BitmapFactory.decodeByteArray(file.bytes, 0, file.bytes.size)
                    ?: return@withContext null

                var currentQuality = quality
                var outputBytes: ByteArray? = null
                var attempt = 0
                val maxAttempts = 15

                do {
                    ensureActive()
                    attempt++

                    ByteArrayOutputStream().use { stream ->
                        bitmap.compress(compressFormat, currentQuality, stream)
                        outputBytes = stream.toByteArray()
                    }

                    val size = outputBytes?.size ?: 0

                    if (size <= compressionThreshold) {
                        return@withContext outputBytes
                    }

                    if (attempt >= maxAttempts) {
                        return@withContext outputBytes
                    }

                    val shouldDownscale = isLossless || currentQuality < 20
                    if (shouldDownscale) {
                        val scaleFactor = 0.75 // Reduce dimensions by 25%
                        val newWidth = (bitmap.width * scaleFactor).roundToInt()
                        val newHeight = (bitmap.height * scaleFactor).roundToInt()

                        if (newWidth < 200 || newHeight < 200) {
                            return@withContext outputBytes
                        }

                        val resized = bitmap.scale(newWidth, newHeight)
                        bitmap = resized

                        if (!isLossless) {
                            currentQuality = (quality * 0.8).toInt().coerceAtLeast(50)
                        }
                    } else {
                        currentQuality = (currentQuality * 0.8).toInt()
                    }

                } while (isActive)

                outputBytes
            } catch (e: Exception) {
                ensureActive()
                e.printStackTrace()
                null
            }
        }
    }
}
