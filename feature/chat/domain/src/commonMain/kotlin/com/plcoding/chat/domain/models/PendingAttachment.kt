package com.plcoding.chat.domain.models

import com.plcoding.core.domain.media.File
import kotlin.time.Instant

data class PendingAttachment(
    val messageAttachment: MessageAttachment,
    val file: File,
    val uploadUrl: String,
    val uploadExpiresAt: Instant,
    val publicUrl: String
)
