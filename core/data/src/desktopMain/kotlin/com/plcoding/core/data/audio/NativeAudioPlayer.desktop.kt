package com.plcoding.core.data.audio

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
import javax.sound.sampled.AudioInputStream
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.Clip
import javax.sound.sampled.LineEvent

actual class NativeAudioPlayer(
    private val scope: CoroutineScope,
    private val audioMetadataExtractor: AudioMetadataExtractor,
    private val audioFileCache: AudioFileCache,
    private val logger: ChirpLogger,
) : AudioPlayer {
    private var clip: Clip? = null
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
                val audioStream = getAudioInputStreamFromFile(cachedFilePath)
                if (audioStream == null) {
                    _playbackState.value = PlaybackState.ERROR
                    _currentPlayingUrl.value = null
                    return@withContext
                }

                setupClipAndPlay(audioStream)
                extractWaveform(cachedFilePath)
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
                val extension = when {
                    mimeType.contains("wav") -> "wav"
                    mimeType.contains("m4a") || mimeType.contains("mp4") -> "m4a"
                    mimeType.contains("mp3") || mimeType.contains("mpeg") -> "mp3"
                    mimeType.contains("ogg") -> "ogg"
                    else -> "wav"
                }

                tempFile = File.createTempFile("playback_", ".$extension")
                tempFile?.let {
                    FileOutputStream(it).use { fos ->
                        fos.write(bytes)
                    }
                }

                val audioStream = AudioSystem.getAudioInputStream(tempFile)
                setupClipAndPlay(audioStream)
                extractWaveform(tempFile!!.absolutePath)
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
            clip?.stop()
            _playbackState.value = PlaybackState.PAUSED
            positionJob?.cancel()
        }
    }

    actual override fun resume() {
        if (_playbackState.value == PlaybackState.PAUSED) {
            clip?.start()
            _playbackState.value = PlaybackState.PLAYING
            startPositionTracking()
        }
    }

    actual override fun stop() {
        positionJob?.cancel()
        clip?.apply {
            runCatching {
                if (isRunning) stop()
                close()
            }
        }
        clip = null
        _playbackState.value = PlaybackState.IDLE
        _currentPosition.value = 0L
        _duration.value = 0L
        _currentPlayingUrl.value = null
        _waveformData.value = emptyList()
        cleanupTempFile()
    }

    actual override fun seekTo(position: Long) {
        clip?.let { c ->
            val framePosition = (position * c.format.frameRate / 1000).toLong()
            c.framePosition = framePosition.toInt().coerceIn(0, c.frameLength)
            _currentPosition.value = position
        }
    }

    actual override fun release() {
        stop()
    }

    private fun getAudioInputStreamFromFile(filePath: String): AudioInputStream? {
        return runCatching {
            val file = File(filePath)
            if (!file.exists()) return null
            AudioSystem.getAudioInputStream(file)
        }.getOrNull()
    }

    private fun setupClipAndPlay(audioStream: AudioInputStream) {
        clip = AudioSystem.getClip().apply {
            addLineListener { event ->
                when (event.type) {
                    LineEvent.Type.STOP -> {
                        if (_playbackState.value == PlaybackState.PLAYING) {
                            _playbackState.value = PlaybackState.IDLE
                            _currentPosition.value = 0L
                            _currentPlayingUrl.value = null
                            positionJob?.cancel()
                            cleanupTempFile()
                        }
                    }
                }
            }
            open(audioStream)
            _duration.value = (frameLength * 1000L / format.frameRate).toLong()
            start()
        }

        _playbackState.value = PlaybackState.PLAYING
        startPositionTracking()
    }

    private fun startPositionTracking() {
        positionJob = scope.launch {
            while (isActive && _playbackState.value == PlaybackState.PLAYING) {
                runCatching {
                    clip?.let { c ->
                        _currentPosition.value =
                            (c.framePosition * 1000L / c.format.frameRate).toLong()
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
