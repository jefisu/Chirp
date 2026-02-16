package com.plcoding.core.domain.audio

interface AudioMetadataExtractor {
    suspend fun extractAmplitudes(path: String): List<Float>
    suspend fun extractDurationMs(path: String): Long
}
