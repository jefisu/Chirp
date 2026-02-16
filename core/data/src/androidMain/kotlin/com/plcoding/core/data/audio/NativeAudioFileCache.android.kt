package com.plcoding.core.data.audio

import android.content.Context
import com.plcoding.core.domain.logging.ChirpLogger
import java.io.File

actual class NativeAudioFileCache(
    private val context: Context,
    logger: ChirpLogger,
) : JvmNativeAudioFileCache(logger) {
    override val cacheDir = File(context.cacheDir, "audio_cache").apply {
        mkdirs()
    }
}
