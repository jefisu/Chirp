package com.plcoding.chat.presentation.model

import com.plcoding.core.domain.media.File

sealed interface VoiceRecordingState {
    data object Idle : VoiceRecordingState

    data class Recording(
        val durationMs: Long,
        val amplitudes: List<Float>
    ) : VoiceRecordingState

    data class Paused(
        val durationMs: Long,
        val waveformData: List<Float>,
        val audioFile: File? = null
    ) : VoiceRecordingState

    data object Sending : VoiceRecordingState
}
