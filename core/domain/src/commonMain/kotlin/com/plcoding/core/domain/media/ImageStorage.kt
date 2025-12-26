package com.plcoding.core.domain.media

interface ImageStorage {
    suspend fun saveImage(bytes: ByteArray, fileName: String? = null): String?
    suspend fun getImage(filePath: String): ByteArray?
}