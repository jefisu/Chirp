@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import platform.AVFoundation.AVMediaTypeAudio
import platform.AVFoundation.AVURLAsset
import platform.AVFoundation.tracksWithMediaType
import platform.CoreMedia.CMTimeGetSeconds
import platform.Foundation.NSURL
import kotlin.math.sin

actual class NativeAudioMetadataExtractor(
    private val logger: ChirpLogger,
) : AudioMetadataExtractor {
    actual override suspend fun extractAmplitudes(path: String): List<Float> {
        return try {
            val url = if (path.startsWith("http")) {
                NSURL.URLWithString(path) ?: return defaultAmplitudes()
            } else {
                NSURL.fileURLWithPath(path)
            }

            extractAmplitudesFromURL(url)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioMetadataExtractor: Failed to extract amplitudes from: $path", e)
            defaultAmplitudes()
        }
    }

    actual override suspend fun extractDurationMs(path: String): Long {
        return try {
            val url =
                if (path.startsWith("http")) {
                    NSURL.URLWithString(path) ?: return 0L
                } else {
                    NSURL.fileURLWithPath(path)
                }
            val asset = AVURLAsset.assetWithURL(url)
            val duration = asset.duration
            val seconds = CMTimeGetSeconds(duration)
            (seconds * 1000).toLong()
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioMetadataExtractor: Failed to extract duration from: $path", e)
            0L
        }
    }

    private fun extractAmplitudesFromURL(url: NSURL): List<Float> {
        return try {
            val asset = AVURLAsset.assetWithURL(url)
            val tracks = asset.tracksWithMediaType(AVMediaTypeAudio)

            if (tracks.isEmpty()) return defaultAmplitudes()

            val duration = asset.duration
            val seconds = CMTimeGetSeconds(duration)

            if (seconds <= 0.0) return defaultAmplitudes()

            val estimatedChunks = 50
            val chunkDuration = seconds / estimatedChunks

            List(estimatedChunks) { i ->
                val chunkStart = i.toDouble() * chunkDuration
                generatePseudoAmplitude(chunkStart, seconds)
            }
        } catch (e: Exception) {
            logger.error("NativeAudioMetadataExtractor: Failed to extract amplitudes from URL", e)
            defaultAmplitudes()
        }
    }

    private fun generatePseudoAmplitude(
        position: Double,
        totalDuration: Double,
    ): Float {
        val baseAmplitude = 0.3 + (position / totalDuration) * 0.3
        val variation = sin(position * 2.0) * 0.15
        return (baseAmplitude + variation).coerceIn(0.1, 0.8).toFloat()
    }

    private fun defaultAmplitudes(): List<Float> = List(50) { 0.5f }
}
