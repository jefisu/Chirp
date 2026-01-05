package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.ChatParticipantDto
import com.plcoding.chat.database.entities.ChatParticipantEntity
import com.plcoding.chat.domain.models.ChatParticipant

fun ChatParticipantDto.toChatParticipant(): ChatParticipant {
    return ChatParticipant(
        userId = userId,
        username = username,
        profilePictureUrl = profilePictureUrl
    )
}

fun ChatParticipantEntity.toChatParticipant(): ChatParticipant {
    return ChatParticipant(
        userId = userId,
        username = username,
        profilePictureUrl = profilePictureUrl
    )
}

fun ChatParticipant.toChatParticipantEntity(): ChatParticipantEntity {
    return ChatParticipantEntity(
        userId = userId,
        username = username,
        profilePictureUrl = profilePictureUrl
    )
}