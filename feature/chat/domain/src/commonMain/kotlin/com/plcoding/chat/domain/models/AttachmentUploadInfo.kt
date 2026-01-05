package com.plcoding.chat.domain.models

import com.plcoding.core.domain.media.File
import kotlin.time.Instant

data class AttachmentUploadInfo(
    val originalFile: File,
    val uploadUrl: String,
    val expiresAt: Instant,
    val publicUrl: String,
)
