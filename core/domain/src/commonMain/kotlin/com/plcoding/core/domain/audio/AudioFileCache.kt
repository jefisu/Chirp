package com.plcoding.core.domain.audio

interface AudioFileCache {
    suspend fun getFile(url: String): String

    suspend fun deleteFile(url: String)

    suspend fun deleteFilesByUrls(urls: List<String>)
}