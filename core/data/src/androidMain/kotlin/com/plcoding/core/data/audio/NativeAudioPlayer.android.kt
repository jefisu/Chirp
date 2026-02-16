package com.plcoding.core.data.audio

import android.media.MediaPlayer
import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.audio.AudioPlayer
import com.plcoding.core.domain.audio.PlaybackState
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

actual class NativeAudioPlayer(
    private val scope: CoroutineScope,
    private val audioMetadataExtractor: AudioMetadataExtractor,
    private val audioFileCache: AudioFileCache,
    private val logger: ChirpLogger,
) : AudioPlayer {
    private var mediaPlayer: MediaPlayer? = null
    private var positionJob: Job? = null
    private var tempFile: File? = null

    private val _playbackState = MutableStateFlow(PlaybackState.IDLE)
    actual override val playbackState: StateFlow<PlaybackState> = _playbackState.asStateFlow()

    private val _currentPosition = MutableStateFlow(0L)
    actual override val currentPosition: StateFlow<Long> = _currentPosition.asStateFlow()

    private val _duration = MutableStateFlow(0L)
    actual override val duration: StateFlow<Long> = _duration.asStateFlow()

    private val _currentPlayingUrl = MutableStateFlow<String?>(null)
    actual override val currentPlayingUrl: StateFlow<String?> = _currentPlayingUrl.asStateFlow()

    private val _waveformData = MutableStateFlow<List<Float>>(emptyList())
    actual override val waveformData: StateFlow<List<Float>> = _waveformData.asStateFlow()

    actual override suspend fun play(url: String) {
        stop()
        _playbackState.value = PlaybackState.LOADING
        _currentPlayingUrl.value = url

        withContext(Dispatchers.IO) {
            try {
                val cachedFilePath = audioFileCache.getFile(url)
                mediaPlayer = MediaPlayer().apply {
                    setDataSource(cachedFilePath)
                    setOnPreparedListener { mp ->
                        _duration.value = mp.duration.toLong()
                        _playbackState.value = PlaybackState.PLAYING
                        mp.start()
                        startPositionTracking()
                        extractWaveform(cachedFilePath)
                    }
                    setOnCompletionListener {
                        _playbackState.value = PlaybackState.IDLE
                        _currentPosition.value = 0L
                        _currentPlayingUrl.value = null
                        positionJob?.cancel()
                    }
                    setOnErrorListener { _, what, extra ->
                        logger.error("NativeAudioPlayer: MediaPlayer error during playback (what=$what, extra=$extra)")
                        _playbackState.value = PlaybackState.ERROR
                        _currentPlayingUrl.value = null
                        true
                    }
                    prepareAsync()
                }
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioPlayer: Failed to play audio from URL: $url", e)
                _playbackState.value = PlaybackState.ERROR
                _currentPlayingUrl.value = null
            }
        }
    }

    actual override suspend fun playFromBytes(
        bytes: ByteArray,
        mimeType: String,
    ) {
        stop()
        _playbackState.value = PlaybackState.LOADING

        withContext(Dispatchers.IO) {
            try {
                val extension =
                    when {
                        mimeType.contains("m4a") || mimeType.contains("mp4") -> "m4a"
                        mimeType.contains("mp3") || mimeType.contains("mpeg") -> "mp3"
                        mimeType.contains("ogg") -> "ogg"
                        mimeType.contains("opus") -> "opus"
                        mimeType.contains("wav") -> "wav"
                        else -> "m4a"
                    }

                tempFile = File.createTempFile("playback_", ".$extension")
                FileOutputStream(tempFile).use { fos ->
                    fos.write(bytes)
                }

                val filePath = tempFile!!.absolutePath
                mediaPlayer = MediaPlayer().apply {
                    setDataSource(filePath)
                    setOnPreparedListener { mp ->
                        _duration.value = mp.duration.toLong()
                        _playbackState.value = PlaybackState.PLAYING
                        mp.start()
                        startPositionTracking()
                        extractWaveform(filePath)
                    }
                    setOnCompletionListener {
                        _playbackState.value = PlaybackState.IDLE
                        _currentPosition.value = 0L
                        positionJob?.cancel()
                        cleanupTempFile()
                    }
                    setOnErrorListener { _, what, extra ->
                        logger.error("NativeAudioPlayer: MediaPlayer error during bytes playback (what=$what, extra=$extra)")
                        _playbackState.value = PlaybackState.ERROR
                        cleanupTempFile()
                        true
                    }
                    prepareAsync()
                }
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioPlayer: Failed to play audio from bytes", e)
                _playbackState.value = PlaybackState.ERROR
                cleanupTempFile()
            }
        }
    }

    actual override fun pause() {
        if (_playbackState.value == PlaybackState.PLAYING) {
            mediaPlayer?.pause()
            _playbackState.value = PlaybackState.PAUSED
            positionJob?.cancel()
        }
    }

    actual override fun resume() {
        if (_playbackState.value == PlaybackState.PAUSED) {
            mediaPlayer?.start()
            _playbackState.value = PlaybackState.PLAYING
            startPositionTracking()
        }
    }

    actual override fun stop() {
        positionJob?.cancel()
        mediaPlayer?.apply {
            try {
                if (isPlaying) stop()
                release()
            } catch (e: Exception) {
                logger.error("NativeAudioPlayer: Error stopping playback", e)
            }
        }
        mediaPlayer = null
        _playbackState.value = PlaybackState.IDLE
        _currentPosition.value = 0L
        _duration.value = 0L
        _currentPlayingUrl.value = null
        _waveformData.value = emptyList()
        cleanupTempFile()
    }

    actual override fun seekTo(position: Long) {
        mediaPlayer?.seekTo(position.toInt())
        _currentPosition.value = position
    }

    actual override fun release() {
        stop()
    }

    private fun startPositionTracking() {
        positionJob = scope.launch {
            while (isActive && _playbackState.value == PlaybackState.PLAYING) {
                runCatching {
                    mediaPlayer?.let {
                        _currentPosition.value = it.currentPosition.toLong()
                    }
                }
                delay(100)
            }
        }
    }

    private fun extractWaveform(path: String) {
        scope.launch {
            val waveform = audioMetadataExtractor.extractAmplitudes(path)
            _waveformData.value = waveform
        }
    }

    private fun cleanupTempFile() {
        tempFile?.delete()
        tempFile = null
    }
}
