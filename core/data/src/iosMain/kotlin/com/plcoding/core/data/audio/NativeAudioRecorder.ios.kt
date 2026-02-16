package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioError
import com.plcoding.core.domain.audio.AudioRecorder
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.Result
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import platform.AVFAudio.AVAudioRecorder
import platform.AVFAudio.AVAudioSession
import platform.AVFAudio.AVAudioSessionCategoryPlayAndRecord
import platform.AVFAudio.AVAudioSessionModeDefault
import platform.AVFAudio.AVEncoderAudioQualityKey
import platform.AVFAudio.AVEncoderBitRateKey
import platform.AVFAudio.AVFormatIDKey
import platform.AVFAudio.AVNumberOfChannelsKey
import platform.AVFAudio.AVSampleRateKey
import platform.AVFAudio.setActive
import platform.CoreAudioTypes.kAudioFormatMPEG4AAC
import platform.Foundation.NSData
import platform.Foundation.NSDate
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.NSUUID
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.timeIntervalSince1970
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class)
actual class NativeAudioRecorder(
    private val scope: CoroutineScope,
    private val logger: ChirpLogger,
) : AudioRecorder {
    private var recorder: AVAudioRecorder? = null
    private var outputFilePath: String? = null
    private var amplitudeJob: Job? = null
    private var durationJob: Job? = null
    private var startTime: Long = 0L
    private var pausedDuration: Long = 0L
    private var isPaused: Boolean = false

    private val _isRecording = MutableStateFlow(false)
    actual override val isRecording: StateFlow<Boolean> = _isRecording.asStateFlow()

    private val _amplitudes = MutableSharedFlow<Float>(extraBufferCapacity = 64)
    actual override val amplitudes: SharedFlow<Float> = _amplitudes.asSharedFlow()

    private val _recordingDuration = MutableStateFlow(0L)
    actual override val recordingDuration: StateFlow<Long> = _recordingDuration.asStateFlow()

    actual override suspend fun startRecording(): Result<Unit, AudioError> {
        if (_isRecording.value) {
            return Result.Failure(AudioError.AlreadyRecording)
        }

        pausedDuration = 0L
        isPaused = false

        return try {
            val audioSession = AVAudioSession.sharedInstance()
            audioSession.setCategory(
                AVAudioSessionCategoryPlayAndRecord,
                mode = AVAudioSessionModeDefault,
                options = 0u,
                error = null
            )
            audioSession.setActive(true, null)

            val fileName = "voice_${NSUUID().UUIDString}.m4a"
            val filePath = NSTemporaryDirectory() + fileName
            outputFilePath = filePath

            val url = NSURL.fileURLWithPath(filePath)

            val settings = mapOf<Any?, Any?>(
                AVFormatIDKey to kAudioFormatMPEG4AAC,
                AVSampleRateKey to 44100.0,
                AVNumberOfChannelsKey to 1,
                AVEncoderBitRateKey to 128000,
                AVEncoderAudioQualityKey to 100
            )

            recorder = AVAudioRecorder(url, settings, null).apply {
                setMeteringEnabled(true)
                prepareToRecord()
                record()
            }

            _isRecording.value = true
            startTime = currentTimeMillis()
            _recordingDuration.value = 0L

            startAmplitudeMonitoring()
            startDurationTracking()

            Result.Success(Unit)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioRecorder: Failed to start recording", e)
            cleanup()
            Result.Failure(AudioError.RecordingFailed)
        }
    }

    actual override suspend fun pauseRecording(): Result<Unit, AudioError> {
        if (!_isRecording.value) {
            return Result.Failure(AudioError.NotRecording)
        }
        if (isPaused) {
            return Result.Failure(AudioError.AlreadyRecording)
        }

        return try {
            recorder?.pause()
            isPaused = true
            Result.Success(Unit)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioRecorder: Failed to pause recording", e)
            Result.Failure(AudioError.RecordingFailed)
        }
    }

    actual override suspend fun resumeRecording(): Result<Unit, AudioError> {
        if (!_isRecording.value) {
            return Result.Failure(AudioError.NotRecording)
        }
        if (!isPaused) {
            return Result.Failure(AudioError.NotRecording)
        }

        return try {
            recorder?.record()
            isPaused = false
            Result.Success(Unit)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioRecorder: Failed to resume recording", e)
            Result.Failure(AudioError.RecordingFailed)
        }
    }

    actual override suspend fun stopRecording(): Result<File, AudioError> {
        if (!_isRecording.value && outputFilePath == null) {
            return Result.Failure(AudioError.NotRecording)
        }

        return try {
            if (recorder != null) {
                recorder?.stop()
                recorder = null
            }
            _isRecording.value = false
            isPaused = false
            amplitudeJob?.cancel()
            durationJob?.cancel()

            val filePath = outputFilePath
            if (filePath != null) {
                val data: NSData? = NSData.dataWithContentsOfFile(filePath)
                if (data != null) {
                    val bytes = data.toByteArray()
                    val fileName = filePath.substringAfterLast("/")
                    NSFileManager.defaultManager.removeItemAtPath(filePath, null)
                    outputFilePath = null
                    return Result.Success(
                        File(
                            name = fileName,
                            mimeType = "audio/m4a",
                            bytes = bytes,
                        ),
                    )
                }
            }

            outputFilePath = null
            Result.Failure(AudioError.FileNotFound)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioRecorder: Failed to stop recording", e)
            cleanup()
            Result.Failure(AudioError.RecordingFailed)
        }
    }

    actual override fun cancelRecording() {
        cleanup()
    }

    private fun startAmplitudeMonitoring() {
        amplitudeJob = scope.launch {
            while (isActive && _isRecording.value) {
                if (!isPaused) {
                    runCatching {
                        recorder?.updateMeters()
                        val averagePower = recorder?.averagePowerForChannel(0u) ?: -160f
                        val normalizedAmplitude = ((averagePower + 45f) / 45f).coerceIn(0f, 1f)
                        _amplitudes.emit(normalizedAmplitude)
                    }
                }
                delay(50)
            }
        }
    }

    private fun startDurationTracking() {
        durationJob = scope.launch {
            while (isActive && _isRecording.value) {
                if (!isPaused) {
                    _recordingDuration.value = currentTimeMillis() - startTime - pausedDuration
                }
                delay(100)
            }
        }
    }

    private fun cleanup() {
        amplitudeJob?.cancel()
        durationJob?.cancel()
        runCatching {
            recorder?.stop()
        }
        recorder = null
        outputFilePath?.let {
            NSFileManager.defaultManager.removeItemAtPath(it, null)
        }
        outputFilePath = null
        _isRecording.value = false
        isPaused = false
        _recordingDuration.value = 0L
        pausedDuration = 0L
    }

    private fun currentTimeMillis(): Long = (NSDate().timeIntervalSince1970 * 1000).toLong()

    private fun NSData.toByteArray(): ByteArray {
        val length = this.length.toInt()
        val bytes = ByteArray(length)
        if (length > 0) {
            bytes.usePinned { pinned ->
                memcpy(pinned.addressOf(0), this.bytes, this.length)
            }
        }
        return bytes
    }
}
