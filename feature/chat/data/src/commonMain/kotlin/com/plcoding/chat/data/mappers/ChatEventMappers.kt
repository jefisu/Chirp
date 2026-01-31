package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.ChatEventDto
import com.plcoding.chat.data.dto.ChatHistoryItemDto
import com.plcoding.chat.data.dto.websocket.IncomingWebSocketDto
import com.plcoding.chat.database.entities.ChatEventEntity
import com.plcoding.chat.database.entities.ChatEventWithUsers
import com.plcoding.chat.domain.models.ChatEvent
import com.plcoding.chat.domain.models.ChatEventType
import com.plcoding.chat.domain.models.ChatHistoryItem
import kotlin.time.Instant
import com.plcoding.chat.domain.models.ChatEventWithUsers as DomainChatEventWithUsers

fun ChatEventDto.toChatEventEntity(): ChatEventEntity {
    return ChatEventEntity(
        eventId = id,
        chatId = chatId,
        eventType = eventType,
        actorUserId = actorUserId,
        targetUserId = targetUserId,
        timestamp = Instant.parse(createdAt).toEpochMilliseconds()
    )
}

fun ChatEventEntity.toChatEvent(): ChatEvent {
    return ChatEvent(
        id = eventId,
        chatId = chatId,
        eventType = ChatEventType.valueOf(eventType),
        actorUserId = actorUserId,
        targetUserId = targetUserId,
        createdAt = Instant.fromEpochMilliseconds(timestamp)
    )
}

fun ChatEvent.toChatEventEntity(): ChatEventEntity {
    return ChatEventEntity(
        eventId = id,
        chatId = chatId,
        eventType = eventType.name,
        actorUserId = actorUserId,
        targetUserId = targetUserId,
        timestamp = createdAt.toEpochMilliseconds()
    )
}

fun ChatEventWithUsers.toDomainChatEventWithUsers(): DomainChatEventWithUsers {
    return DomainChatEventWithUsers(
        event = event.toChatEvent(),
        actor = actor.toChatParticipant(),
        target = target?.toChatParticipant()
    )
}

fun ChatHistoryItemDto.toChatHistoryItem(): ChatHistoryItem {
    return when (this) {
        is ChatHistoryItemDto.Message -> ChatHistoryItem.Message(
            message = message.toChatMessage(),
            createdAt = Instant.parse(createdAt)
        )
        is ChatHistoryItemDto.Event -> ChatHistoryItem.Event(
            event = event.toChatEventEntity().toChatEvent(),
            createdAt = Instant.parse(createdAt)
        )
    }
}

fun IncomingWebSocketDto.ChatEventDto.toChatEventEntity(): ChatEventEntity {
    return ChatEventEntity(
        eventId = eventId,
        chatId = chatId,
        eventType = eventType,
        actorUserId = actorUserId,
        targetUserId = targetUserId,
        timestamp = Instant.parse(createdAt).toEpochMilliseconds()
    )
}
