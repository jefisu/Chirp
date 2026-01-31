package com.plcoding.chat.domain.models

import kotlin.time.Instant

data class ChatEvent(
    val id: String,
    val chatId: String,
    val eventType: ChatEventType,
    val actorUserId: String,
    val targetUserId: String?,
    val createdAt: Instant
)
