package com.plcoding.chat.domain.models

data class ChatEventWithUsers(
    val event: ChatEvent,
    val actor: ChatParticipant,
    val target: ChatParticipant?
)
