package com.plcoding.chat.domain.chat

import com.plcoding.chat.domain.models.ChatEventWithUsers
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ConnectionState
import com.plcoding.chat.domain.models.TypingEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

data class ChatDeletedEvent(
    val chatId: String,
    val deletedByUserId: String
)

data class RemovedFromChatEvent(
    val chatId: String,
    val removedByUserId: String,
    val removedByUsername: String
)

interface ChatConnectionClient {
    val chatMessages: Flow<ChatMessage>
    val connectionState: StateFlow<ConnectionState>
    val typingEvents: Flow<TypingEvent>
    val chatEvents: Flow<ChatEventWithUsers>
    val chatDeletedEvents: Flow<ChatDeletedEvent>
    val removedFromChatEvents: Flow<RemovedFromChatEvent>
    suspend fun sendTypingEvent(chatId: String, isTyping: Boolean)
}
