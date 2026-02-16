package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioError
import com.plcoding.core.domain.audio.AudioRecorder
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.Result
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import javax.sound.sampled.AudioFileFormat
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioInputStream
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.DataLine
import javax.sound.sampled.TargetDataLine
import kotlin.math.abs
import kotlin.math.log10
import java.io.File as JavaFile

actual class NativeAudioRecorder(
    private val scope: CoroutineScope,
    private val logger: ChirpLogger,
) : AudioRecorder {
    private var targetLine: TargetDataLine? = null
    private var recordingJob: Job? = null
    private var amplitudeJob: Job? = null
    private var durationJob: Job? = null
    private var outputFile: JavaFile? = null
    private var startTime: Long = 0L
    private var pausedDuration: Long = 0L
    private var pauseStartTime: Long = 0L
    private var isPaused: Boolean = false
    private val audioBuffer = ByteArrayOutputStream()

    private val _isRecording = MutableStateFlow(false)
    actual override val isRecording: StateFlow<Boolean> = _isRecording.asStateFlow()

    private val _amplitudes = MutableSharedFlow<Float>(extraBufferCapacity = 64)
    actual override val amplitudes: SharedFlow<Float> = _amplitudes.asSharedFlow()

    private val _recordingDuration = MutableStateFlow(0L)
    actual override val recordingDuration: StateFlow<Long> = _recordingDuration.asStateFlow()

    private val audioFormat = AudioFormat(
        44100f,
        16,
        1,
        true,
        false
    )

    actual override suspend fun startRecording(): Result<Unit, AudioError> {
        if (_isRecording.value) {
            return Result.Failure(AudioError.AlreadyRecording)
        }

        pausedDuration = 0L
        isPaused = false

        return withContext(Dispatchers.IO) {
            try {
                val info = DataLine.Info(TargetDataLine::class.java, audioFormat)
                if (!AudioSystem.isLineSupported(info)) {
                    return@withContext Result.Failure(AudioError.RecordingFailed)
                }

                targetLine = (AudioSystem.getLine(info) as TargetDataLine).apply {
                    open(audioFormat)
                    start()
                }

                audioBuffer.reset()
                _isRecording.value = true
                startTime = System.currentTimeMillis()
                _recordingDuration.value = 0L

                startRecordingJob()
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
    }

    actual override suspend fun pauseRecording(): Result<Unit, AudioError> {
        if (!_isRecording.value) {
            return Result.Failure(AudioError.NotRecording)
        }
        if (isPaused) {
            return Result.Failure(AudioError.AlreadyRecording)
        }

        return withContext(Dispatchers.IO) {
            try {
                targetLine?.stop()
                pauseStartTime = System.currentTimeMillis()
                isPaused = true
                Result.Success(Unit)
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioRecorder: Failed to pause recording", e)
                Result.Failure(AudioError.RecordingFailed)
            }
        }
    }

    actual override suspend fun resumeRecording(): Result<Unit, AudioError> {
        if (!_isRecording.value) {
            return Result.Failure(AudioError.NotRecording)
        }
        if (!isPaused) {
            return Result.Failure(AudioError.NotRecording)
        }

        return withContext(Dispatchers.IO) {
            try {
                pausedDuration += System.currentTimeMillis() - pauseStartTime
                targetLine?.start()
                isPaused = false
                Result.Success(Unit)
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioRecorder: Failed to resume recording", e)
                Result.Failure(AudioError.RecordingFailed)
            }
        }
    }

    actual override suspend fun stopRecording(): Result<File, AudioError> {
        if (!_isRecording.value && audioBuffer.size() == 0) {
            return Result.Failure(AudioError.NotRecording)
        }

        return withContext(Dispatchers.IO) {
            try {
                recordingJob?.cancel()
                amplitudeJob?.cancel()
                durationJob?.cancel()

                runCatching {
                    targetLine?.stop()
                    targetLine?.close()
                }
                targetLine = null
                isPaused = false

                val tempFile = JavaFile.createTempFile("voice_", ".wav")
                outputFile = tempFile

                val audioData = audioBuffer.toByteArray()

                if (audioData.isNotEmpty()) {
                    val audioInputStream = AudioInputStream(
                        audioData.inputStream(),
                        audioFormat,
                        audioData.size.toLong() / audioFormat.frameSize
                    )

                    AudioSystem.write(
                        audioInputStream,
                        AudioFileFormat.Type.WAVE,
                        tempFile
                    )

                    val bytes = tempFile.readBytes()
                    val result = File(
                        name = tempFile.name,
                        mimeType = "audio/wav",
                        bytes = bytes
                    )

                    tempFile.delete()
                    outputFile = null
                    audioBuffer.reset()
                    _isRecording.value = false

                    Result.Success(result)
                } else {
                    tempFile.delete()
                    outputFile = null
                    audioBuffer.reset()
                    _isRecording.value = false
                    Result.Failure(AudioError.FileNotFound)
                }
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                logger.error("NativeAudioRecorder: Failed to stop recording", e)
                cleanup()
                Result.Failure(AudioError.RecordingFailed)
            }
        }
    }

    actual override fun cancelRecording() {
        cleanup()
    }

    private fun startRecordingJob() {
        recordingJob = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(4096)
            while (isActive && _isRecording.value) {
                if (!isPaused) {
                    runCatching {
                        val bytesRead = targetLine?.read(buffer, 0, buffer.size) ?: 0
                        if (bytesRead > 0) {
                            synchronized(audioBuffer) {
                                audioBuffer.write(buffer, 0, bytesRead)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun startAmplitudeMonitoring() {
        amplitudeJob = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(1024)
            while (isActive && _isRecording.value) {
                if (!isPaused) {
                    runCatching {
                        val bytesRead = targetLine?.read(buffer, 0, buffer.size) ?: 0
                        if (bytesRead > 0) {
                            var sum = 0.0
                            for (i in 0 until bytesRead step 2) {
                                val sample =
                                    (buffer[i + 1].toInt() shl 8) or (buffer[i].toInt() and 0xFF)
                                sum += abs(sample.toDouble())
                            }
                            val average = sum / (bytesRead / 2)

                            if (average > 0) {
                                val db = 20 * log10(average / 32768.0)
                                val normalizedAmplitude =
                                    ((db + 45) / 45).coerceIn(0.0, 1.0).toFloat()
                                _amplitudes.emit(normalizedAmplitude)
                            } else {
                                _amplitudes.emit(0f)
                            }
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
        recordingJob?.cancel()
        amplitudeJob?.cancel()
        durationJob?.cancel()
        runCatching {
            targetLine?.stop()
            targetLine?.close()
        }
        targetLine = null
        outputFile?.delete()
        outputFile = null
        audioBuffer.reset()
        _isRecording.value = false
        isPaused = false
        _recordingDuration.value = 0L
        pausedDuration = 0L
    }
}
