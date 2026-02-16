package com.plcoding.chat.presentation.model

import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.core.designsystem.components.avatar.ChatParticipantUi
import com.plcoding.core.presentation.util.UiText

data class ChatUi(
    val id: String,
    val localParticipant: ChatParticipantUi,
    val otherParticipants: List<ChatParticipantUi>,
    val lastMessage: ChatMessage?,
    val lastMessageSenderUsername: String?,
    val lastMessageFormattedDate: UiText?,
    val lastMessageAudioDuration: Long? = null,
    val creatorId: String?,
    val isCurrentUserAdmin: Boolean = false
)
