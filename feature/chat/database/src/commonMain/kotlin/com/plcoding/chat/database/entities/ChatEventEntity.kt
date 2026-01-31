package com.plcoding.chat.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = ChatEntity::class,
            parentColumns = ["chatId"],
            childColumns = ["chatId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("chatId"),
        Index("timestamp"),
        Index("actorUserId"),
        Index("targetUserId")
    ]
)
data class ChatEventEntity(
    @PrimaryKey
    val eventId: String,
    val chatId: String,
    val eventType: String,
    val actorUserId: String,
    val targetUserId: String?,
    val timestamp: Long
)
