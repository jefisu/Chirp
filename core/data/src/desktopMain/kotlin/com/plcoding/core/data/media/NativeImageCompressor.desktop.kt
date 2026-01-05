package com.plcoding.core.data.media

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
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

            // Return original bytes if ImageIO cannot read the format (e.g. WebP), otherwise return null on failure.
            val image = ImageIO.read(inputStream) ?: return@withContext file.bytes

            val format = when (file.mimeType) {
                "image/png" -> "png"
                "image/jpeg" -> "jpg"
                "image/webp" -> "webp"
                else -> "jpg"
            }

            if (format == "png") {
                val outputStream = ByteArrayOutputStream()
                ImageIO.write(image, "png", outputStream)
                return@withContext outputStream.toByteArray()
            }

            var currentQuality = quality
            var outputBytes: ByteArray

            val writers = ImageIO.getImageWritersByFormatName(format)
            val writer = if (writers.hasNext()) writers.next() else {
                val jpgWriters = ImageIO.getImageWritersByFormatName("jpg")
                if (jpgWriters.hasNext()) jpgWriters.next() else return@withContext null
            }

            try {
                val param = writer.defaultWriteParam
                if (param.canWriteCompressed()) {
                    param.compressionMode = ImageWriteParam.MODE_EXPLICIT
                }

                do {
                    ensureActive()
                    val outputStream = ByteArrayOutputStream()
                    val imageOutputStream = ImageIO.createImageOutputStream(outputStream)
                    writer.output = imageOutputStream

                    if (param.canWriteCompressed()) {
                        param.compressionQuality = currentQuality / 100f
                    }

                    writer.write(null, IIOImage(image, null, null), param)
                    imageOutputStream.close()

                    outputBytes = outputStream.toByteArray()
                    currentQuality -= (currentQuality * 0.1).roundToInt()
                } while (
                    outputBytes.size > compressionThreshold &&
                    currentQuality > 5 &&
                    param.canWriteCompressed()
                )
            } finally {
                writer.dispose()
            }

            outputBytes
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
