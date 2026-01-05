package com.plcoding.chat.database.view

import androidx.room.DatabaseView
import com.plcoding.chat.database.entities.MessageAttachmentEntity

@DatabaseView(
    viewName = "last_message_view_per_chat",
    value = """
        SELECT 
            m1.*, 
            p.username AS senderUsername,
            GROUP_CONCAT(i.id || '::::' || i.url || '::::' || i.messageId || '::::' || i.type || '::::' || i.status, '||||') AS attachments
        FROM chatmessageentity m1
        JOIN (
            SELECT chatId, MAX(timestamp) AS max_timestamp
            FROM chatmessageentity
            GROUP BY chatId
        ) m2 ON m1.chatId = m2.chatId AND m1.timestamp = m2.max_timestamp
        LEFT JOIN chatparticipantentity p ON m1.senderId = p.userId
        LEFT JOIN messageattachmententity i ON m1.messageId = i.messageId
        GROUP BY m1.messageId
    """
)
data class LastMessageView(
    val messageId: String,
    val chatId: String,
    val senderId: String,
    val content: String?,
    val timestamp: Long,
    val deliveryStatus: String,
    val senderUsername: String?,
    val attachments: List<MessageAttachmentEntity>
)
