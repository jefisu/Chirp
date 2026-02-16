package com.plcoding.chat.domain.audio

data class AudioMetadata(
    val attachmentId: String,
    val durationMs: Long,
    val amplitudes: List<Float>,
)
