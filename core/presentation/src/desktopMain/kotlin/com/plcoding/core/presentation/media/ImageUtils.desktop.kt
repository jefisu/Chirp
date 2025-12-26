package com.plcoding.core.presentation.media

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.file.Files
import javax.imageio.ImageIO

suspend fun File.toPickedImageData(): PickedImageData? {
    return withContext(Dispatchers.IO) {
        try {
            val mimeType = getMimeTypeFromFileName(name)
            val bytes = Files.readAllBytes(toPath())

            var width = 0
            var height = 0

            try {
                val stream = ByteArrayInputStream(bytes)
                val bufferedImage = ImageIO.read(stream)
                if (bufferedImage != null) {
                    width = bufferedImage.width
                    height = bufferedImage.height
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }

            PickedImageData(
                bytes = bytes,
                mimeType = mimeType,
                name = name,
                width = width,
                height = height
            )
        } catch (_: Exception) {
            coroutineContext.ensureActive()
            null
        }
    }
}

fun getMimeTypeFromFileName(fileName: String): String? {
    val extension = fileName.substringAfterLast(".", "").lowercase()
    return when (extension) {
        "png" -> "image/png"
        "jpg", "jpeg" -> "image/jpeg"
        "webp" -> "image/webp"
        else -> null
    }
}

val allowedImageExtensions = listOf(
    "png",
    "jpg",
    "jpeg",
    "webp",
)