package com.plcoding.core.data.audio

import android.content.Context
import android.media.MediaRecorder
import android.os.Build
import com.plcoding.core.domain.audio.AudioError
import com.plcoding.core.domain.audio.AudioRecorder
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.Result
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
import kotlin.math.log10
import java.io.File as JavaFile

actual class NativeAudioRecorder(
    private val scope: CoroutineScope,
    private val context: Context,
    private val logger: ChirpLogger,
) : AudioRecorder {
    private var mediaRecorder: MediaRecorder? = null
    private var outputFile: JavaFile? = null
    private var amplitudeJob: Job? = null
    private var durationJob: Job? = null
    private var startTime: Long = 0L
    private var pausedDuration: Long = 0L
    private var pauseStartTime: Long = 0L
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
            val tempFile = JavaFile.createTempFile("voice_", ".m4a")
            outputFile = tempFile

            mediaRecorder = createMediaRecorder().apply {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
                setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
                setAudioEncodingBitRate(128000)
                setAudioSamplingRate(44100)
                setOutputFile(tempFile.absolutePath)
                prepare()
                start()
            }

            _isRecording.value = true
            startTime = System.currentTimeMillis()
            _recordingDuration.value = 0L

            startAmplitudeMonitoring()
            startDurationTracking()

            Result.Success(Unit)
        } catch (e: SecurityException) {
            logger.error("NativeAudioRecorder: Permission denied to start recording", e)
            cleanup()
            Result.Failure(AudioError.PermissionDenied)
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
            mediaRecorder?.pause()
            pauseStartTime = System.currentTimeMillis()
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
            pausedDuration += System.currentTimeMillis() - pauseStartTime
            mediaRecorder?.resume()
            isPaused = false
            Result.Success(Unit)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            logger.error("NativeAudioRecorder: Failed to resume recording", e)
            Result.Failure(AudioError.RecordingFailed)
        }
    }

    actual override suspend fun stopRecording(): Result<File, AudioError> {
        if (!_isRecording.value && outputFile == null) {
            return Result.Failure(AudioError.NotRecording)
        }

        return try {
            if (mediaRecorder != null) {
                mediaRecorder?.apply {
                    stop()
                    release()
                }
            }
            mediaRecorder = null
            _isRecording.value = false
            isPaused = false
            amplitudeJob?.cancel()
            durationJob?.cancel()

            val file = outputFile
            if (file != null && file.exists()) {
                val bytes = file.readBytes()
                val result = File(
                    name = file.name,
                    mimeType = "audio/m4a",
                    bytes = bytes,
                )
                file.delete()
                outputFile = null
                return result.let { Result.Success(it) }
            }

            if (outputFile != null) {
                outputFile = null
            }

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

    private fun createMediaRecorder(): MediaRecorder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(context)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }

    private fun startAmplitudeMonitoring() {
        amplitudeJob = scope.launch {
            while (isActive && _isRecording.value) {
                if (!isPaused) {
                    runCatching {
                        val maxAmplitude = mediaRecorder?.maxAmplitude ?: 0
                        if (maxAmplitude > 0) {
                            val db = 20 * log10(maxAmplitude.toDouble() / 32767.0)
                            val normalizedAmplitude =
                                ((db + 45) / 45).coerceIn(0.0, 1.0).toFloat()
                            _amplitudes.emit(normalizedAmplitude)
                        } else {
                            _amplitudes.emit(0f)
                        }
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
                    _recordingDuration.value =
                        System.currentTimeMillis() - startTime - pausedDuration
                }
                delay(100)
            }
        }
    }

    private fun cleanup() {
        amplitudeJob?.cancel()
        durationJob?.cancel()
        runCatching {
            mediaRecorder?.stop()
            mediaRecorder?.release()
        }
        mediaRecorder = null
        outputFile?.delete()
        outputFile = null
        _isRecording.value = false
        isPaused = false
        _recordingDuration.value = 0L
        pausedDuration = 0L
    }
}
