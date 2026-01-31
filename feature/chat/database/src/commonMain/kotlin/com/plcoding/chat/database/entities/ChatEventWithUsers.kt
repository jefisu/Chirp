package com.plcoding.chat.database.entities

import androidx.room.Embedded
import androidx.room.Relation

data class ChatEventWithUsers(
    @Embedded
    val event: ChatEventEntity,
    @Relation(
        parentColumn = "actorUserId",
        entityColumn = "userId"
    )
    val actor: ChatParticipantEntity,
    @Relation(
        parentColumn = "targetUserId",
        entityColumn = "userId"
    )
    val target: ChatParticipantEntity?
)
