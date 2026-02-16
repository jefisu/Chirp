package com.plcoding.core.domain.audio

import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.Result
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

interface AudioRecorder {
    val isRecording: StateFlow<Boolean>
    val amplitudes: SharedFlow<Float>
    val recordingDuration: StateFlow<Long>

    suspend fun startRecording(): Result<Unit, AudioError>
    suspend fun pauseRecording(): Result<Unit, AudioError>
    suspend fun resumeRecording(): Result<Unit, AudioError>
    suspend fun stopRecording(): Result<File, AudioError>
    fun cancelRecording()
}
