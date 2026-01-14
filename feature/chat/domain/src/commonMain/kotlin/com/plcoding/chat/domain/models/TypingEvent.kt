package com.plcoding.chat.domain.models

data class TypingEvent(
    val chatId: String,
    val userId: String,
    val userName: String,
    val isTyping: Boolean
)
