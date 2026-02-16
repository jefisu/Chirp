@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.dataWithContentsOfURL
import platform.Foundation.writeToFile

actual class NativeAudioFileCache(
    private val logger: ChirpLogger,
) : AudioFileCache {
    private val cacheDir: String
        get() = NSTemporaryDirectory() + "audio_cache"

    private val mutex = Mutex()

    private val urlToFileMap = mutableMapOf<String, String>()

    init {
        NSFileManager.defaultManager.createDirectoryAtPath(
            cacheDir,
            true,
            null,
            null,
        )
    }

    actual override suspend fun getFile(url: String): String =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                urlToFileMap[url]?.let { cachedPath ->
                    if (NSFileManager.defaultManager.fileExistsAtPath(cachedPath)) {
                        return@withContext cachedPath
                    }
                    urlToFileMap.remove(url)
                }

                val file = downloadAndCache(url)
                urlToFileMap[url] = file
                file
            }
        }

    actual override suspend fun deleteFile(url: String) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                urlToFileMap[url]?.let { path ->
                    try {
                        NSFileManager.defaultManager.removeItemAtPath(path, null)
                    } catch (e: Exception) {
                        currentCoroutineContext().ensureActive()
                        logger.error("NativeAudioFileCache: Failed to delete cached file", e)
                    }
                }
                urlToFileMap.remove(url)
            }
        }
    }

    actual override suspend fun deleteFilesByUrls(urls: List<String>) {
        withContext(Dispatchers.IO) {
            urls.forEach { url ->
                urlToFileMap[url]?.let { path ->
                    try {
                        NSFileManager.defaultManager.removeItemAtPath(path, null)
                    } catch (e: Exception) {
                        logger.error("NativeAudioFileCache: Failed to delete cached file", e)
                    }
                }
                urlToFileMap.remove(url)
            }
        }
    }

    private suspend fun downloadAndCache(url: String): String =
        withContext(Dispatchers.IO) {
            val fileName = generateFileName(url)
            val filePath = "$cacheDir/$fileName"

            if (!NSFileManager.defaultManager.fileExistsAtPath(filePath)) {
                val nsUrl = NSURL.URLWithString(url)
                if (nsUrl == null) {
                    logger.error("NativeAudioFileCache: Invalid URL: $url")
                    return@withContext filePath
                }
                val data = NSData.dataWithContentsOfURL(nsUrl)
                if (data == null) {
                    logger.error("NativeAudioFileCache: Failed to download audio from: $url")
                    return@withContext filePath
                }
                data.writeToFile(filePath, true)
            }

            filePath
        }

    private fun generateFileName(url: String): String {
        val hash = url.fold(0L) { acc, char ->
            (acc * 31 + char.code)
        }
        return "$hash.audio"
    }
}
