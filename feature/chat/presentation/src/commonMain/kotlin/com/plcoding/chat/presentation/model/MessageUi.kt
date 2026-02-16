package com.plcoding.chat.presentation.model

import com.plcoding.chat.domain.models.ChatEventType
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.core.designsystem.components.avatar.ChatParticipantUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.presentation.util.UiText

sealed interface MessageUi {
    val id: String

    sealed interface LocalUser : MessageUi {
        val deliveryStatus: ChatMessageDeliveryStatus
        val formattedSentTime: UiText

        data class Message(
            override val id: String,
            val content: String?,
            val attachments: List<MessageAttachmentUi>,
            override val deliveryStatus: ChatMessageDeliveryStatus,
            override val formattedSentTime: UiText,
        ) : LocalUser

        data class Audio(
            override val id: String,
            val attachment: MessageAttachmentUi.Audio,
            override val deliveryStatus: ChatMessageDeliveryStatus,
            override val formattedSentTime: UiText,
        ) : LocalUser
    }

    sealed interface OtherUser : MessageUi {
        val sender: ChatParticipantUi
        val formattedSentTime: UiText

        data class Message(
            override val id: String,
            val content: String?,
            val attachments: List<MessageAttachmentUi>,
            override val sender: ChatParticipantUi,
            override val formattedSentTime: UiText,
        ) : OtherUser

        data class Audio(
            override val id: String,
            val attachment: MessageAttachmentUi.Audio,
            override val sender: ChatParticipantUi,
            override val formattedSentTime: UiText,
        ) : OtherUser
    }

    data class DateSeparator(
        override val id: String,
        val date: UiText,
    ) : MessageUi

    data class SystemEvent(
        override val id: String,
        val eventType: ChatEventType,
        val actorUsername: String,
        val targetUsername: String?,
        val formattedTime: UiText,
        val isLocalUserActor: Boolean,
    ) : MessageUi
}
