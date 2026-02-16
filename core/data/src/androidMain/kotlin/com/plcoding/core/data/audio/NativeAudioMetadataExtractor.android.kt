package com.plcoding.core.data.audio

import android.media.MediaExtractor
import android.media.MediaFormat
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import kotlin.math.abs

actual class NativeAudioMetadataExtractor(
    private val logger: ChirpLogger,
) : AudioMetadataExtractor {
    actual override suspend fun extractAmplitudes(path: String): List<Float> =
        withContext(Dispatchers.IO) {
            val extractor = MediaExtractor()
            try {
                extractor.setDataSource(path)
                val trackIndex = (0 until extractor.trackCount).firstOrNull {
                    extractor
                        .getTrackFormat(it)
                        .getString(MediaFormat.KEY_MIME)
                        ?.startsWith("audio/") == true
                } ?: return@withContext emptyList()

                val format = extractor.getTrackFormat(trackIndex)
                val durationUs = format.getLong(MediaFormat.KEY_DURATION)
                if (durationUs <= 0) return@withContext emptyList()

                extractor.selectTrack(trackIndex)

                val sampleRate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE)
                val channelCount = format.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
                val bytesPerSample = 2
                val bytesPerFrame = bytesPerSample * channelCount
                val totalSamples = ((durationUs / 1_000_000.0) * sampleRate).toLong()

                val targetSize = 50
                val samplesPerChunk = (totalSamples / targetSize).coerceAtLeast(1)

                val amplitudes = mutableListOf<Float>()

                var currentSample = 0L
                while (currentSample < totalSamples) {
                    extractor.seekTo(
                        currentSample * 1_000_000 / sampleRate,
                        MediaExtractor.SEEK_TO_CLOSEST_SYNC,
                    )

                    var maxAbs = 0f
                    var samplesInChunk = 0
                    val chunkBuffer = ByteBuffer.allocate(bytesPerFrame * 1024)

                    while (samplesInChunk < samplesPerChunk && currentSample < totalSamples) {
                        val bytesRead = extractor.readSampleData(chunkBuffer, 0)
                        if (bytesRead <= 0) break

                        chunkBuffer.rewind()
                        for (i in 0 until bytesRead step bytesPerFrame) {
                            if (i + 1 < bytesRead) {
                                val sample = chunkBuffer.getShort(i).toInt()
                                val normalized = abs(sample) / 32768f
                                if (normalized > maxAbs) maxAbs = normalized
                                samplesInChunk++
                                if (samplesInChunk >= samplesPerChunk) break
                            }
                        }
                        currentSample += samplesInChunk
                        if (!extractor.advance()) break
                    }

                    amplitudes.add(maxAbs)
                }

                extractor.release()

                if (amplitudes.isEmpty()) return@withContext emptyList()
                amplitudes.take(targetSize)
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioMetadataExtractor: Failed to extract amplitudes from: $path", e)
                emptyList()
            } finally {
                extractor.release()
            }
        }

    actual override suspend fun extractDurationMs(path: String): Long =
        withContext(Dispatchers.IO) {
            val extractor = MediaExtractor()
            try {
                extractor.setDataSource(path)
                val trackIndex = (0 until extractor.trackCount).firstOrNull {
                    extractor
                        .getTrackFormat(it)
                        .getString(MediaFormat.KEY_MIME)
                        ?.startsWith("audio/") == true
                } ?: return@withContext 0L

                val format = extractor.getTrackFormat(trackIndex)
                val durationUs = format.getLong(MediaFormat.KEY_DURATION)
                durationUs / 1000
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioMetadataExtractor: Failed to extract duration from: $path", e)
                0L
            } finally {
                extractor.release()
            }
        }
}
