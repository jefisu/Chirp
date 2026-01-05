package com.plcoding.chat.data.dto

import kotlinx.serialization.Serializable

@Serializable
data class MessageAttachmentDto(
    val id: String,
    val url: String,
    val type: String,
)
