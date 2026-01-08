package com.plcoding.core.data.media

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.awt.Image
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam
import kotlin.math.roundToInt

actual class NativeImageCompressor : ImageCompressor {
    actual override suspend fun compressImage(
        file: File,
        compressionThreshold: Long,
        quality: Int
    ): ByteArray? = withContext(Dispatchers.Default) {
        try {
            val inputStream = ByteArrayInputStream(file.bytes)
            var image = ImageIO.read(inputStream) ?: return@withContext file.bytes

            val format = when (file.mimeType) {
                "image/png" -> "png"
                "image/jpeg" -> "jpg"
                "image/webp" -> "webp"
                else -> "jpg"
            }

            val isPng = format == "png"

            var currentQuality = quality
            var outputBytes: ByteArray? = null
            var attempt = 0
            val maxAttempts = 15

            do {
                ensureActive()
                attempt++

                val outputStream = ByteArrayOutputStream()

                if (isPng) {
                    ImageIO.write(image, "png", outputStream)
                    outputBytes = outputStream.toByteArray()
                } else {
                    val writers = ImageIO.getImageWritersByFormatName(format)
                    val writer = if (writers.hasNext()) writers.next() else {
                        val jpgWriters = ImageIO.getImageWritersByFormatName("jpg")
                        if (jpgWriters.hasNext()) jpgWriters.next() else return@withContext null
                    }

                    val imageOutputStream = ImageIO.createImageOutputStream(outputStream)
                    writer.output = imageOutputStream

                    try {
                        val param = writer.defaultWriteParam
                        if (param.canWriteCompressed()) {
                            param.compressionMode = ImageWriteParam.MODE_EXPLICIT
                            param.compressionQuality = currentQuality / 100f
                        }
                        writer.write(null, IIOImage(image, null, null), param)
                    } finally {
                        writer.dispose()
                        imageOutputStream.close()
                    }
                    outputBytes = outputStream.toByteArray()
                }

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
                    val newWidth = (image.width * scaleFactor).roundToInt()
                    val newHeight = (image.height * scaleFactor).roundToInt()

                    if (newWidth < 200 || newHeight < 200) {
                        return@withContext outputBytes
                    }

                    val resized = BufferedImage(newWidth, newHeight, image.type)
                    val g = resized.createGraphics()
                    g.drawImage(
                        image.getScaledInstance(newWidth, newHeight, Image.SCALE_SMOOTH),
                        0,
                        0,
                        null
                    )
                    g.dispose()

                    image = resized

                    if (!isPng) {
                        currentQuality = (quality * 0.8).toInt().coerceAtLeast(50)
                    }
                } else {
                    currentQuality = (currentQuality * 0.8).toInt()
                }

            } while (isActive)

            outputBytes
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
