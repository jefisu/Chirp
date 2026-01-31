package com.plcoding.chat.presentation.model

import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.core.designsystem.components.avatar.ChatParticipantUi

data class ChatUi(
    val id: String,
    val localParticipant: ChatParticipantUi,
    val otherParticipants: List<ChatParticipantUi>,
    val lastMessage: ChatMessage?,
    val lastMessageSenderUsername: String?,
    val creatorId: String?,
    val isCurrentUserAdmin: Boolean = false
)
