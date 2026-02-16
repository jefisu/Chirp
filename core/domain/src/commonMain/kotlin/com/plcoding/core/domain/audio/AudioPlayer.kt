package com.plcoding.core.domain.audio

import kotlinx.coroutines.flow.StateFlow

interface AudioPlayer {
    val playbackState: StateFlow<PlaybackState>
    val currentPosition: StateFlow<Long>
    val duration: StateFlow<Long>
    val currentPlayingUrl: StateFlow<String?>
    val waveformData: StateFlow<List<Float>>

    suspend fun play(url: String)
    suspend fun playFromBytes(bytes: ByteArray, mimeType: String)
    fun pause()
    fun resume()
    fun stop()
    fun seekTo(position: Long)
    fun release()
}
