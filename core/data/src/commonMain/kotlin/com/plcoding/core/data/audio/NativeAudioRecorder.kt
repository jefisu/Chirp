package com.plcoding.core.data.audio

import com.plcoding.core.domain.audio.AudioError
import com.plcoding.core.domain.audio.AudioRecorder
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.Result
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

expect class NativeAudioRecorder : AudioRecorder {
    override val isRecording: StateFlow<Boolean>
    override val amplitudes: SharedFlow<Float>
    override val recordingDuration: StateFlow<Long>

    override suspend fun startRecording(): Result<Unit, AudioError>
    override suspend fun pauseRecording(): Result<Unit, AudioError>
    override suspend fun resumeRecording(): Result<Unit, AudioError>
    override suspend fun stopRecording(): Result<File, AudioError>
    override fun cancelRecording()
}
