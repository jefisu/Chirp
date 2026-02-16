package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioPlayer
import com.plcoding.core.domain.audio.PlaybackState
import kotlinx.coroutines.flow.StateFlow

expect class NativeAudioPlayer : AudioPlayer {
    override val playbackState: StateFlow<PlaybackState>
    override val currentPosition: StateFlow<Long>
    override val duration: StateFlow<Long>
    override val currentPlayingUrl: StateFlow<String?>
    override val waveformData: StateFlow<List<Float>>

    override suspend fun play(url: String)
    override suspend fun playFromBytes(bytes: ByteArray, mimeType: String)
    override fun pause()
    override fun resume()
    override fun stop()
    override fun seekTo(position: Long)
    override fun release()
}
