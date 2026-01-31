package com.plcoding.chat.data.dto

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("itemType")
sealed interface ChatHistoryItemDto {
    @Serializable
    @SerialName("MESSAGE")
    data class Message(
        val message: ChatMessageDto,
        val createdAt: String
    ) : ChatHistoryItemDto

    @Serializable
    @SerialName("EVENT")
    data class Event(
        val event: ChatEventDto,
        val createdAt: String
    ) : ChatHistoryItemDto
}
