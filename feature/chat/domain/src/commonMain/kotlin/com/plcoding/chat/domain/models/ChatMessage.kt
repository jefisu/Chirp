package com.plcoding.chat.domain.models

import kotlin.time.Instant

data class ChatMessage(
    val id: String,
    val chatId: String,
    val content: String?,
    val attachments: List<MessageAttachment>,
    val createdAt: Instant,
    val senderId: String,
    val deliveryStatus: ChatMessageDeliveryStatus,
)
