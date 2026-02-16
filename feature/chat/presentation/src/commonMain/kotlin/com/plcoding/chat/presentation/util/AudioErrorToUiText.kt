package com.plcoding.chat.presentation.util

import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.audio_already_recording
import chirp.feature.chat.presentation.generated.resources.audio_file_not_found
import chirp.feature.chat.presentation.generated.resources.audio_not_recording
import chirp.feature.chat.presentation.generated.resources.audio_permission_denied
import chirp.feature.chat.presentation.generated.resources.audio_playback_failed
import chirp.feature.chat.presentation.generated.resources.audio_recording_failed
import chirp.feature.chat.presentation.generated.resources.audio_unknown_error
import chirp.feature.chat.presentation.generated.resources.audio_unsupported_format
import com.plcoding.core.domain.audio.AudioError
import com.plcoding.core.presentation.util.UiText

fun AudioError.toUiText(): UiText =
    when (this) {
        AudioError.PermissionDenied -> UiText.Resource(Res.string.audio_permission_denied)
        AudioError.RecordingFailed -> UiText.Resource(Res.string.audio_recording_failed)
        AudioError.PlaybackFailed -> UiText.Resource(Res.string.audio_playback_failed)
        AudioError.FileNotFound -> UiText.Resource(Res.string.audio_file_not_found)
        AudioError.AlreadyRecording -> UiText.Resource(Res.string.audio_already_recording)
        AudioError.NotRecording -> UiText.Resource(Res.string.audio_not_recording)
        AudioError.UnsupportedFormat -> UiText.Resource(Res.string.audio_unsupported_format)
        AudioError.Unknown -> UiText.Resource(Res.string.audio_unknown_error)
    }
