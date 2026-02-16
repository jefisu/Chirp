package com.plcoding.core.data.audio

import com.plcoding.core.domain.logging.ChirpLogger
import okio.FileSystem
import java.io.File

actual class NativeAudioFileCache(
    logger: ChirpLogger,
) : JvmNativeAudioFileCache(logger) {
    override val cacheDir = File(
        FileSystem.SYSTEM_TEMPORARY_DIRECTORY.toFile(),
        "audio_cache",
    ).apply { mkdirs() }
}