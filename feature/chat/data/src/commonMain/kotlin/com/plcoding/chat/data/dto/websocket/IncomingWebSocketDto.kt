package com.plcoding.chat.data.dto.websocket

import com.plcoding.chat.data.dto.MessageAttachmentDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

enum class IncomingWebSocketType {
    NEW_MESSAGE,
    MESSAGE_DELETED,
    PROFILE_PICTURE_UPDATED,
    CHAT_PARTICIPANTS_CHANGED,
    TYPING_EVENT
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
}
