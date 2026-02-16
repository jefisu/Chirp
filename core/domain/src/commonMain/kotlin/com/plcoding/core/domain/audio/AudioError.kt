package com.plcoding.core.domain.audio

import com.plcoding.core.domain.util.Error

enum class AudioError : Error {
    PermissionDenied,
    RecordingFailed,
    PlaybackFailed,
    FileNotFound,
    AlreadyRecording,
    NotRecording,
    UnsupportedFormat,
    Unknown
}
