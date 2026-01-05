package com.plcoding.chat.domain.models

import com.plcoding.core.domain.media.File

data class OutgoingNewMessage(
    val chatId: String,
    val messageId: String,
    val content: String?,
    val media: List<File> = emptyList()
)
