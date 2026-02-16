package com.plcoding.chat.presentation.model

import com.plcoding.core.domain.audio.PlaybackState

data class AudioPlaybackState(
    val playingAttachmentId: String? = null,
    val playbackState: PlaybackState = PlaybackState.IDLE,
    val currentPosition: Long = 0L,
    val duration: Long = 0L,
    val waveformData: List<Float> = emptyList(),
)
