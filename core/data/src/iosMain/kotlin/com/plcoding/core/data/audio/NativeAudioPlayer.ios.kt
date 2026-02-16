package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.audio.AudioPlayer
import com.plcoding.core.domain.audio.PlaybackState
import com.plcoding.core.domain.logging.ChirpLogger
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.memScoped
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
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
import platform.AVFAudio.AVAudioPlayer
import platform.AVFAudio.AVAudioPlayerDelegateProtocol
import platform.AVFAudio.AVAudioSession
import platform.AVFAudio.AVAudioSessionCategoryPlayback
import platform.AVFAudio.AVAudioSessionModeDefault
import platform.AVFAudio.setActive
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.NSUUID
import platform.Foundation.create
import platform.Foundation.dataWithContentsOfURL
import platform.Foundation.writeToFile
import platform.darwin.NSObject

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual class NativeAudioPlayer(
    private val scope: CoroutineScope,
    private val audioMetadataExtractor: AudioMetadataExtractor,
    private val audioFileCache: AudioFileCache,
    private val logger: ChirpLogger,
) : AudioPlayer {
    private var player: AVAudioPlayer? = null
    private var positionJob: Job? = null
    private var tempFilePath: String? = null
    private var playerDelegate: AudioPlayerDelegate? = null

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
        if (_currentPlayingUrl.value != url) {
            _waveformData.value = emptyList()
        }
        stop()
        _playbackState.value = PlaybackState.LOADING

        withContext(Dispatchers.IO) {
            try {
                setupAudioSession()

                val cachedFilePath = audioFileCache.getFile(url)
                val fileUrl = NSURL.fileURLWithPath(cachedFilePath)

                val data = NSData.dataWithContentsOfURL(fileUrl)
                if (data == null) {
                    _playbackState.value = PlaybackState.ERROR
                    return@withContext
                }

                playerDelegate = AudioPlayerDelegate(
                    onComplete = {
                        _playbackState.value = PlaybackState.IDLE
                        _currentPosition.value = 0L
                        _currentPlayingUrl.value = null
                        positionJob?.cancel()
                    },
                    onError = {
                        _playbackState.value = PlaybackState.ERROR
                        _currentPlayingUrl.value = null
                    },
                    logger = logger,
                )

                val waveformFileName = "waveform_${NSUUID().UUIDString}.m4a"
                val waveformFilePath = NSTemporaryDirectory() + waveformFileName
                tempFilePath = waveformFilePath
                data.writeToFile(waveformFilePath, true)

                player = AVAudioPlayer(data, null).apply {
                    delegate = playerDelegate
                    prepareToPlay()
                    _duration.value = (duration * 1000).toLong()
                }

                if (player?.play() == true) {
                    _currentPlayingUrl.value = url
                    _playbackState.value = PlaybackState.PLAYING
                    startPositionTracking()
                } else {
                    _playbackState.value = PlaybackState.ERROR
                    return@withContext
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
        _waveformData.value = emptyList()
        stop()
        _playbackState.value = PlaybackState.LOADING

        withContext(Dispatchers.IO) {
            try {
                setupAudioSession()

                val extension = when {
                    mimeType.contains("m4a") || mimeType.contains("mp4") -> "m4a"
                    mimeType.contains("mp3") || mimeType.contains("mpeg") -> "mp3"
                    mimeType.contains("ogg") -> "ogg"
                    mimeType.contains("opus") -> "opus"
                    mimeType.contains("wav") -> "wav"
                    else -> "m4a"
                }

                val fileName = "playback_${NSUUID().UUIDString}.$extension"
                val filePath = NSTemporaryDirectory() + fileName
                tempFilePath = filePath

                val data = bytes.toNSData()
                data.writeToFile(filePath, true)

                val url = NSURL.fileURLWithPath(filePath)

                playerDelegate = AudioPlayerDelegate(
                    onComplete = {
                        _playbackState.value = PlaybackState.IDLE
                        _currentPosition.value = 0L
                        positionJob?.cancel()
                        cleanupTempFile()
                    },
                    onError = {
                        _playbackState.value = PlaybackState.ERROR
                        cleanupTempFile()
                    },
                    logger = logger,
                )

                player = AVAudioPlayer(url, null).apply {
                    delegate = playerDelegate
                    prepareToPlay()
                    _duration.value = (duration * 1000).toLong()
                }

                if (player?.play() == true) {
                    _playbackState.value = PlaybackState.PLAYING
                    startPositionTracking()
                } else {
                    _playbackState.value = PlaybackState.ERROR
                    cleanupTempFile()
                    return@withContext
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
            player?.pause()
            _playbackState.value = PlaybackState.PAUSED
            positionJob?.cancel()
        }
    }

    actual override fun resume() {
        if (_playbackState.value == PlaybackState.PAUSED) {
            player?.play()
            _playbackState.value = PlaybackState.PLAYING
            startPositionTracking()
        }
    }

    actual override fun stop() {
        positionJob?.cancel()
        player?.stop()
        player = null
        playerDelegate = null
        _playbackState.value = PlaybackState.IDLE
        _currentPosition.value = 0L
        _duration.value = 0L
        _currentPlayingUrl.value = null
        cleanupTempFile()
    }

    actual override fun seekTo(position: Long) {
        player?.currentTime = position / 1000.0
        _currentPosition.value = position
    }

    actual override fun release() {
        stop()
    }

    private fun setupAudioSession() {
        val audioSession = AVAudioSession.sharedInstance()
        audioSession.setCategory(
            AVAudioSessionCategoryPlayback,
            mode = AVAudioSessionModeDefault,
            options = 0u,
            error = null,
        )
        audioSession.setActive(true, null)
    }

    private fun startPositionTracking() {
        positionJob = scope.launch {
            while (isActive && _playbackState.value == PlaybackState.PLAYING) {
                runCatching {
                    player?.let {
                        _currentPosition.value = (it.currentTime * 1000).toLong()
                    }
                }
                delay(100)
            }
        }
    }

    private fun cleanupTempFile() {
        tempFilePath?.let {
            NSFileManager.defaultManager.removeItemAtPath(it, null)
        }
        tempFilePath = null
    }

    private fun ByteArray.toNSData(): NSData =
        memScoped {
            NSData.create(
                bytes = allocArrayOf(this@toNSData),
                length = this@toNSData.size.toULong()
            )
        }

    private class AudioPlayerDelegate(
        private val onComplete: () -> Unit,
        private val onError: () -> Unit,
        private val logger: ChirpLogger,
    ) : NSObject(),
        AVAudioPlayerDelegateProtocol {
        override fun audioPlayerDidFinishPlaying(
            player: AVAudioPlayer,
            successfully: Boolean,
        ) {
            if (successfully) {
                onComplete()
            } else {
                onError()
            }
        }

        override fun audioPlayerDecodeErrorDidOccur(
            player: AVAudioPlayer,
            error: NSError?,
        ) {
            logger.error("NativeAudioPlayer: Decode error occurred: ${error?.localizedDescription}")
            onError()
        }
    }
}
