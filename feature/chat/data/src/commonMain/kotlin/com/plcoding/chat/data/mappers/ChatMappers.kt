package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.ChatDto
import com.plcoding.chat.database.entities.ChatEntity
import com.plcoding.chat.database.entities.ChatInfoEntity
import com.plcoding.chat.database.entities.ChatWithParticipants
import com.plcoding.chat.database.entities.MessageWithSender
import com.plcoding.chat.domain.models.Chat
import com.plcoding.chat.domain.models.ChatInfo
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.domain.models.ChatParticipant
import com.plcoding.chat.domain.models.MessageAttachment
import kotlin.time.Instant

typealias DataMessageWithSender = MessageWithSender
typealias DomainMessageWithSender = com.plcoding.chat.domain.models.MessageWithSender

fun ChatDto.toChat(): Chat {
    val lastMessageSenderUsername = lastMessage?.let { message ->
        participants.find { it.userId == message.senderId }?.username
    }
    return Chat(
        id = id,
        participants = participants.map { it.toChatParticipant() },
        lastActivityAt = Instant.parse(lastActivityAt),
        lastMessage = lastMessage?.toChatMessage(),
        lastMessageSenderUsername = lastMessageSenderUsername
    )
}

fun ChatEntity.toChat(
    participants: List<ChatParticipant>,
    lastMessage: ChatMessage? = null
): Chat {
    val lastMessageSenderUsername = lastMessage?.let { message ->
        participants.find { it.userId == message.senderId }?.username
    }
    return Chat(
        id = chatId,
        participants = participants,
        lastActivityAt = Instant.fromEpochMilliseconds(lastActivityAt),
        lastMessage = lastMessage,
        lastMessageSenderUsername = lastMessageSenderUsername
    )
}

fun ChatWithParticipants.toChat(
    attachments: List<MessageAttachment>,
): Chat {
    return Chat(
        id = chat.chatId,
        participants = participants.map { it.toChatParticipant() },
        lastActivityAt = Instant.fromEpochMilliseconds(chat.lastActivityAt),
        lastMessage = lastMessage?.toChatMessage(attachments),
        lastMessageSenderUsername = lastMessage?.senderUsername
    )
}

fun Chat.toChatEntity(): ChatEntity {
    return ChatEntity(
        chatId = id,
        lastActivityAt = lastActivityAt.toEpochMilliseconds()
    )
}

fun DataMessageWithSender.toMessageWithSender(): DomainMessageWithSender {
    return DomainMessageWithSender(
        message = message.toChatMessage(attachments = attachments.map { it.toMessageAttachment() }),
        sender = sender.toChatParticipant(),
        deliveryStatus = ChatMessageDeliveryStatus.valueOf(this.message.deliveryStatus)
    )
}

fun ChatInfoEntity.toChatInfo(): ChatInfo {
    return ChatInfo(
        chat = chat.toChat(
            participants = this.participants.map { it.toChatParticipant() }
        ),
        messages = messagesWithSenders.map { it.toMessageWithSender() }
    )
}