package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioFileCache

expect class NativeAudioFileCache : AudioFileCache {
    override suspend fun getFile(url: String): String

    override suspend fun deleteFile(url: String)

    override suspend fun deleteFilesByUrls(urls: List<String>)
}

const val CACHE_MAX_SIZE_BYTES = 100L * 1024 * 1024 // 100MB
