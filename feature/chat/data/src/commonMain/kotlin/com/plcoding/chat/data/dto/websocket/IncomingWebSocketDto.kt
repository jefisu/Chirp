package com.plcoding.chat.data.dto.websocket

import com.plcoding.chat.data.dto.MessageAttachmentDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

enum class IncomingWebSocketType {
    NEW_MESSAGE,
    MESSAGE_DELETED,
    PROFILE_PICTURE_UPDATED,
    CHAT_PARTICIPANTS_CHANGED,
    TYPING_EVENT,
    CHAT_EVENT,
    CHAT_DELETED,
    REMOVED_FROM_CHAT
}

@Serializable
sealed interface IncomingWebSocketDto {

    @Serializable
    data class NewMessageDto(
        val id: String,
        val chatId: String,
        val content: String?,
        val senderId: String,
        val createdAt: String,
        @SerialName("attachedFiles")
        val attachments: List<MessageAttachmentDto>,
        val type: IncomingWebSocketType = IncomingWebSocketType.NEW_MESSAGE
    ): IncomingWebSocketDto

    @Serializable
    data class MessageDeletedDto(
        val messageId: String,
        val chatId: String,
        val type: IncomingWebSocketType = IncomingWebSocketType.MESSAGE_DELETED
    ): IncomingWebSocketDto

    @Serializable
    data class ProfilePictureUpdated(
        val userId: String,
        val newUrl: String?,
        val type: IncomingWebSocketType = IncomingWebSocketType.PROFILE_PICTURE_UPDATED
    ): IncomingWebSocketDto

    @Serializable
    data class ChatParticipantsChangedDto(
        val chatId: String,
        val type: IncomingWebSocketType = IncomingWebSocketType.CHAT_PARTICIPANTS_CHANGED
    ): IncomingWebSocketDto

    @Serializable
    data class TypingEventDto(
        val chatId: String,
        val userId: String,
        val userName: String,
        val isTyping: Boolean,
        val type: IncomingWebSocketType = IncomingWebSocketType.TYPING_EVENT
    ): IncomingWebSocketDto

    @Serializable
    data class ChatEventDto(
        val chatId: String,
        val eventId: String,
        val eventType: String,
        val actorUserId: String,
        val actorUsername: String,
        val targetUserId: String? = null,
        val targetUsername: String? = null,
        val createdAt: String,
        val type: IncomingWebSocketType = IncomingWebSocketType.CHAT_EVENT
    ): IncomingWebSocketDto

    @Serializable
    data class ChatDeletedDto(
        val chatId: String,
        val deletedByUserId: String,
        val type: IncomingWebSocketType = IncomingWebSocketType.CHAT_DELETED
    ): IncomingWebSocketDto

    @Serializable
    data class RemovedFromChatDto(
        val chatId: String,
        val removedByUserId: String,
        val removedByUsername: String,
        val type: IncomingWebSocketType = IncomingWebSocketType.REMOVED_FROM_CHAT
    ): IncomingWebSocketDto
}
