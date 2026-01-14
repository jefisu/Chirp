package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.websocket.IncomingWebSocketDto
import com.plcoding.chat.domain.models.TypingEvent

fun IncomingWebSocketDto.TypingEventDto.toTypingEvent(): TypingEvent {
    return TypingEvent(
        chatId = chatId,
        userId = userId,
        userName = userName,
        isTyping = isTyping
    )
}
