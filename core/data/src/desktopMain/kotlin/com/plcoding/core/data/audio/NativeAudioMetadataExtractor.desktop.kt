package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import javax.sound.sampled.AudioSystem
import kotlin.math.abs

actual class NativeAudioMetadataExtractor(
    private val audioFileCache: AudioFileCache,
    private val logger: ChirpLogger,
) : AudioMetadataExtractor {
    actual override suspend fun extractAmplitudes(path: String): List<Float> =
        withContext(Dispatchers.IO) {
            try {
                val cachedFilePath =
                    if (path.startsWith("http")) {
                        audioFileCache.getFile(path)
                    } else {
                        path
                    }

                val file = File(cachedFilePath)
                if (!file.exists()) return@withContext emptyList()

                val targetSize = 50

                try {
                    AudioSystem.getAudioInputStream(file).use { audioInputStream ->
                        val format = audioInputStream.format
                        val sampleSizeInBits = format.sampleSizeInBits

                        if (sampleSizeInBits != 16) {
                            return@withContext List(targetSize) { 0.5f }
                        }

                        val bytesPerFrame = format.frameSize
                        val totalBytes = file.length()
                        val bytesPerChunk = (totalBytes / targetSize).toInt().coerceAtLeast(bytesPerFrame)
                        val amplitudes = mutableListOf<Float>()

                        val buffer = ByteArray(bytesPerChunk)
                        var bytesRead: Int

                        while (audioInputStream.read(buffer).also { bytesRead = it } != -1) {
                            if (bytesRead < bytesPerFrame) break

                            var maxAbs = 0f
                            for (i in 0 until bytesRead step bytesPerFrame) {
                                if (i + 1 >= bytesRead) break
                                val sample =
                                    if (format.isBigEndian) {
                                        (buffer[i].toInt() shl 8) or (buffer[i + 1].toInt() and 0xFF)
                                    } else {
                                        (buffer[i + 1].toInt() shl 8) or (buffer[i].toInt() and 0xFF)
                                    }
                                val normalized = abs(sample) / 32768f
                                if (normalized > maxAbs) maxAbs = normalized
                            }
                            amplitudes.add(maxAbs)
                        }

                        if (amplitudes.isEmpty()) return@withContext emptyList()
                        amplitudes.take(targetSize)
                    }
                } catch (e: Exception) {
                    currentCoroutineContext().ensureActive()
                    logger.error("NativeAudioMetadataExtractor: Failed to extract amplitudes from: $cachedFilePath", e)
                    List(targetSize) { 0.5f }
                }
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioMetadataExtractor: Failed to extract amplitudes from: $path", e)
                List(50) { 0.5f }
            }
        }

    actual override suspend fun extractDurationMs(path: String): Long =
        withContext(Dispatchers.IO) {
            try {
                val cachedFilePath =
                    if (path.startsWith("http")) {
                        audioFileCache.getFile(path)
                    } else {
                        path
                    }

                val file = File(cachedFilePath)
                if (!file.exists()) return@withContext 0L

                val audioFile = AudioSystem.getAudioFileFormat(file)
                val format = audioFile.format
                val frames = audioFile.frameLength
                val durationInSeconds = frames / format.frameRate
                (durationInSeconds * 1000).toLong()
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioMetadataExtractor: Failed to extract duration from: $path", e)
                0L
            }
        }
}
