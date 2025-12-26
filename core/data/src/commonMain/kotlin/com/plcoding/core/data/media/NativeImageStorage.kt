package com.plcoding.core.data.media

import com.plcoding.core.domain.media.ImageStorage

expect class NativeImageStorage: ImageStorage {
    override suspend fun saveImage(bytes: ByteArray, fileName: String?): String?
    override suspend fun getImage(filePath: String): ByteArray?
}