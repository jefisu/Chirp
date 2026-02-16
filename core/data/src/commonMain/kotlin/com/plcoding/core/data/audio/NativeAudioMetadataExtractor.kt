package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioMetadataExtractor

expect class NativeAudioMetadataExtractor : AudioMetadataExtractor {
    override suspend fun extractAmplitudes(path: String): List<Float>
    override suspend fun extractDurationMs(path: String): Long
}
