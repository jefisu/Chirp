@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey
import kotlin.uuid.ExperimentalUuidApi

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = ChatMessageEntity::class,
            parentColumns = ["messageId"],
            childColumns = ["messageId"],
            onDelete = ForeignKey.CASCADE
        )
    ]
)
data class MessageAttachmentEntity(
    @PrimaryKey
    val id: String,
    val url: String,
    val messageId: String,
    val type: String,
    val status: AttachmentUploadStatus = AttachmentUploadStatus.PENDING
)

enum class AttachmentUploadStatus {
    PENDING,
    UPLOADING,
    UPLOADED,
    FAILED
}
