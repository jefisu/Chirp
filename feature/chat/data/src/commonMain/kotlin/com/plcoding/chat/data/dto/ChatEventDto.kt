package com.plcoding.chat.data.dto

import kotlinx.serialization.Serializable

@Serializable
data class ChatEventDto(
    val id: String,
    val chatId: String,
    val eventType: String,
    val actorUserId: String,
    val actorUsername: String,
    val targetUserId: String? = null,
    val targetUsername: String? = null,
    val createdAt: String
)
