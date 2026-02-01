@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.presentation.util

import androidx.compose.foundation.text.input.TextFieldState
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.presentation.chat_detail.ChatDetailState
import com.plcoding.chat.presentation.model.ChatUi
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.components.avatar.ChatParticipantUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUploadStatusUi
import com.plcoding.core.presentation.util.UiText
import kotlin.time.Clock
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object ChatPreviewData {

    val localParticipant = ChatParticipantUi(
        id = "1",
        username = "Philipp",
        initials = "PH",
    )

    val otherParticipant1 = ChatParticipantUi(
        id = "2",
        username = "Cinderella",
        initials = "CI",
    )

    val otherParticipant2 = ChatParticipantUi(
        id = "3",
        username = "Josh",
        initials = "JO",
    )

    val chatUi = ChatUi(
        id = "1",
        localParticipant = localParticipant,
        otherParticipants = listOf(otherParticipant1, otherParticipant2),
        lastMessage = ChatMessage(
            id = "1",
            chatId = "1",
            content = "This is a last chat message",
            createdAt = Clock.System.now(),
            senderId = "1",
            deliveryStatus = ChatMessageDeliveryStatus.SENT,
            attachments = emptyList(),
        ),
        lastMessageSenderUsername = "Philipp",
        isCurrentUserAdmin = false,
        creatorId = null
    )

    val attachmentImages = ('a'..'f').map {
        MessageAttachmentUi.Image(
            id = it.toString(),
            url = it.toString(),
            status = MessageAttachmentUploadStatusUi.PENDING,
        )
    }

    val messages = (1..20).map {
        if (it % 2 == 0) {
            MessageUi.LocalUserMessage(
                id = Uuid.random().toString(),
                content = "Hello world!",
                deliveryStatus = ChatMessageDeliveryStatus.SENT,
                formattedSentTime = UiText.DynamicString("Friday, Aug 20"),
                attachments = if (it == 2) attachmentImages else emptyList(),
            )
        } else {
            MessageUi.OtherUserMessage(
                id = Uuid.random().toString(),
                content = "Hello world!",
                sender = otherParticipant2,
                formattedSentTime = UiText.DynamicString("Friday, Aug 20"),
                attachments = emptyList(),
            )
        }
    }

    val typingUsers = mapOf(
        otherParticipant1.id to otherParticipant1.username,
        otherParticipant2.id to otherParticipant2.username
    )

    val stateWithMessagesAndTyping = ChatDetailState(
        chatUi = chatUi,
        messages = messages.take(10),
        typingUsers = typingUsers,
        messageTextFieldState = TextFieldState(initialText = "Philipp is typing..."),
        canSendMessage = true
    )
}
