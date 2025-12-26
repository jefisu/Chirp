package com.plcoding.core.data.media

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.ImageCompressor

expect class NativeImageCompressor(): ImageCompressor {
    override suspend fun compressImage(
        file: File,
        compressionThreshold: Long,
        quality: Int
    ): ByteArray?
}