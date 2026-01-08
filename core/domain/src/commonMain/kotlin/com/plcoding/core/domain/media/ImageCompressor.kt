package com.plcoding.core.domain.media

interface ImageCompressor {
    suspend fun compressImage(
        file: File,
        compressionThreshold: Long = COMPRESSION_THRESHOLD,
        quality: Int = DEFAULT_QUALITY
    ): ByteArray?

    companion object {
        const val COMPRESSION_THRESHOLD = 1024 * 1024L // 1 MB
        const val DEFAULT_QUALITY = 90
    }
}