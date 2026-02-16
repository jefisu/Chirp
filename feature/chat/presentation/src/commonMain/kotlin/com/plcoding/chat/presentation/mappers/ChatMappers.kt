package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.models.Chat
import com.plcoding.chat.presentation.model.ChatUi
import com.plcoding.chat.presentation.util.DateUtils
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

fun Chat.toUi(
    localParticipantId: String,
    audioDurationMs: Long? = null
): ChatUi {
    val (local, other) = participants.partition { it.userId == localParticipantId }
    val timeZone = TimeZone.currentSystemDefault()
    return ChatUi(
        id = id,
        localParticipant = local.first().toUi(),
        otherParticipants = other.map { it.toUi() },
        lastMessage = lastMessage,
        lastMessageSenderUsername = lastMessageSenderUsername,
        lastMessageFormattedDate = lastMessage?.createdAt?.let {
            DateUtils.formatDateSeparator(it.toLocalDateTime(timeZone).date)
        },
        lastMessageAudioDuration = audioDurationMs,
        isCurrentUserAdmin = creatorId == localParticipantId,
        creatorId = creatorId
    )
}