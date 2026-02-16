package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

abstract class JvmNativeAudioFileCache(
    private val logger: ChirpLogger,
) : AudioFileCache {
    protected abstract val cacheDir: File

    private val mutex = Mutex()
    private val urlToFileMap = mutableMapOf<String, File>()

    override suspend fun getFile(url: String): String =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                urlToFileMap[url]?.let { cachedFile ->
                    if (cachedFile.exists()) {
                        return@withContext cachedFile.absolutePath
                    }
                    urlToFileMap.remove(url)
                }

                val file = downloadAndCache(url)
                urlToFileMap[url] = file
                enforceMaxSize()
                file.absolutePath
            }
        }

    override suspend fun deleteFile(url: String) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                urlToFileMap.remove(url)?.delete()
            }
        }
    }

    override suspend fun deleteFilesByUrls(urls: List<String>) {
        withContext(Dispatchers.IO) {
            urls.forEach { url ->
                urlToFileMap.remove(url)?.delete()
            }
        }
    }

    private suspend fun downloadAndCache(url: String): File =
        withContext(Dispatchers.IO) {
            val fileName = generateFileName(url)
            val file = File(cacheDir, fileName)

            if (!file.exists()) {
                downloadFile(url, file)
            }

            file
        }

    private fun downloadFile(
        urlString: String,
        targetFile: File,
    ) {
        try {
            val url = URL(urlString)
            val connection = url.openConnection() as HttpURLConnection
            connection.connect()

            connection.inputStream.use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (e: Exception) {
            logger.error("JvmNativeAudioFileCache: Failed to download audio from: $urlString", e)
        }
    }

    private suspend fun enforceMaxSize() =
        withContext(Dispatchers.IO) {
            val currentSize = cacheDir.listFiles()?.sumOf { it.length() } ?: 0L
            if (currentSize > CACHE_MAX_SIZE_BYTES) {
                logger.debug("JvmNativeAudioFileCache: Cache size exceeded (${currentSize / 1024 / 1024}MB), evicting old files")
                val files =
                    cacheDir.listFiles()?.sortedBy { it.lastModified() } ?: return@withContext
                var sizeToRemove = currentSize - CACHE_MAX_SIZE_BYTES

                for (file in files) {
                    if (sizeToRemove <= 0) break
                    val fileSize = file.length()
                    if (file.delete()) {
                        sizeToRemove -= fileSize
                        urlToFileMap.entries.removeIf { it.value == file }
                    }
                }
            }
        }

    private fun generateFileName(url: String): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(url.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}
