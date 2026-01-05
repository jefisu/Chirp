@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = MessageAttachmentEntity::class,
            parentColumns = ["id"],
            childColumns = ["attachmentId"],
            onDelete = ForeignKey.CASCADE
        )
    ]
)
data class PendingAttachmentEntity(
    @PrimaryKey
    val id: String = Uuid.random().toHexString(),
    val attachmentId: String,
    val messageId: String,
    val uploadUrl: String,
    val expiresAt: Long,
    val localPath: String,
    val publicUrl: String
)
