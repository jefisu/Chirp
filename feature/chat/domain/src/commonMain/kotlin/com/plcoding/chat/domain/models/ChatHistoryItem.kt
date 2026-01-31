package com.plcoding.chat.domain.models

import kotlin.time.Instant

sealed interface ChatHistoryItem {
    val createdAt: Instant

    data class Message(
        val message: ChatMessage,
        override val createdAt: Instant
    ) : ChatHistoryItem

    data class Event(
        val event: ChatEvent,
        override val createdAt: Instant
    ) : ChatHistoryItem
}
