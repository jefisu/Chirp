package com.plcoding.core.data.media

import com.plcoding.core.domain.media.ImageStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import kotlin.time.Clock

actual class NativeImageStorage : ImageStorage {
    actual override suspend fun saveImage(bytes: ByteArray, fileName: String?): String? {
        return withContext(Dispatchers.IO) {
            val imageFileName = fileName ?: ("image_${Clock.System.now()}.jpg")
            val file = File(System.getProperty("java.io.tmpdir"), imageFileName)
            try {
                FileOutputStream(file).use { stream ->
                    stream.write(bytes)
                }
                file.absolutePath
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }
    }

    actual override suspend fun getImage(filePath: String): ByteArray? {
        return withContext(Dispatchers.IO) {
            val file = File(filePath)
            try {
                file.readBytes()
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }
    }
}