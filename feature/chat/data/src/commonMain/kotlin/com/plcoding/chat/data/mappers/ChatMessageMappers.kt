package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.ChatMessageDto
import com.plcoding.chat.data.dto.websocket.IncomingWebSocketDto
import com.plcoding.chat.data.dto.websocket.OutgoingWebSocketDto
import com.plcoding.chat.database.entities.ChatMessageEntity
import com.plcoding.chat.database.entities.MessageWithSender
import com.plcoding.chat.database.view.LastMessageView
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.domain.models.MessageAttachment
import kotlin.time.Clock
import kotlin.time.Instant


fun ChatMessageDto.toChatMessage(): ChatMessage {
    return ChatMessage(
        id = id,
        chatId = chatId,
        content = content,
        attachments = attachments.map { it.toMessageAttachment() },
        createdAt = Instant.parse(createdAt),
        senderId = senderId,
        deliveryStatus = ChatMessageDeliveryStatus.SENT
    )
}

fun MessageWithSender.toChatMessage(): ChatMessage {
    return message
        .toChatMessage(
            attachments = attachments.map { it.toMessageAttachment() }
        )
}

fun ChatMessageEntity.toChatMessage(
    attachments: List<MessageAttachment>,
): ChatMessage {
    return ChatMessage(
        id = messageId,
        chatId = chatId,
        content = content,
        attachments = attachments,
        createdAt = Instant.fromEpochMilliseconds(timestamp),
        senderId = senderId,
        deliveryStatus = ChatMessageDeliveryStatus.valueOf(deliveryStatus)
    )
}


fun LastMessageView.toChatMessage(
    attachments: List<MessageAttachment>,
): ChatMessage {
    return ChatMessage(
        id = messageId,
        chatId = chatId,
        content = content,
        attachments = attachments,
        createdAt = Instant.fromEpochMilliseconds(timestamp),
        senderId = senderId,
        deliveryStatus = ChatMessageDeliveryStatus.valueOf(this.deliveryStatus),
    )
}

fun ChatMessage.toChatMessageEntity(): ChatMessageEntity {
    return ChatMessageEntity(
        messageId = id,
        chatId = chatId,
        senderId = senderId,
        content = content,
        timestamp = createdAt.toEpochMilliseconds(),
        deliveryStatus = deliveryStatus.name
    )
}

fun ChatMessage.toLastMessageView(): LastMessageView {
    return LastMessageView(
        messageId = id,
        chatId = chatId,
        senderId = senderId,
        content = content,
        timestamp = createdAt.toEpochMilliseconds(),
        deliveryStatus = deliveryStatus.name,
        senderUsername = null
    )
}

fun ChatMessage.toNewMessage(): OutgoingWebSocketDto.NewMessage {
    return OutgoingWebSocketDto.NewMessage(
        messageId = id,
        chatId = chatId,
        content = content,
        attachments = attachments.map { it.toMessageAttachmentDto() }
    )
}

fun IncomingWebSocketDto.NewMessageDto.toChatMessageEntity(): ChatMessageEntity {
    return ChatMessageEntity(
        messageId = id,
        chatId = chatId,
        senderId = senderId,
        content = content,
        timestamp = Instant.parse(createdAt).toEpochMilliseconds(),
        deliveryStatus = ChatMessageDeliveryStatus.SENT.name
    )
}

fun OutgoingWebSocketDto.NewMessage.toChatMessageEntity(
    senderId: String,
    deliveryStatus: ChatMessageDeliveryStatus
): ChatMessageEntity {
    return ChatMessageEntity(
        messageId = messageId,
        chatId = chatId,
        content = content.toString(),
        senderId = senderId,
        deliveryStatus = deliveryStatus.name,
        timestamp = Clock.System.now().toEpochMilliseconds()
    )
}
