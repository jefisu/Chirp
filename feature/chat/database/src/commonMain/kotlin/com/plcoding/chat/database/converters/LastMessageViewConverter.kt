package com.plcoding.chat.database.converters

import androidx.room.TypeConverter
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.MessageAttachmentEntity

/**
 * Convert specifically designed for LastMessageView to handle GROUP_CONCAT results.
 * Converts a custom delimited string into a List<MessageAttachmentEntity>.
 */
class LastMessageViewConverter {

    @TypeConverter
    fun fromMessageAttachmentEntityString(value: String?): List<MessageAttachmentEntity> {
        if (value.isNullOrBlank()) return emptyList()
        return value.split("||||").mapNotNull { row ->
            val parts = row.split("::::")
            if (parts.size == 5) {
                MessageAttachmentEntity(
                    id = parts[0],
                    url = parts[1],
                    messageId = parts[2],
                    type = parts[3],
                    status = AttachmentUploadStatus.valueOf(parts[4])
                )
            } else {
                null
            }
        }
    }

    @TypeConverter
    fun toMessageAttachmentEntityString(list: List<MessageAttachmentEntity>): String {
        return list.joinToString("||||") {
            "${it.id}::::${it.url}::::${it.messageId}::::${it.type}::::${it.status.name}"
        }
    }
}
