package com.plcoding.chat.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import com.plcoding.chat.database.entities.PendingAttachmentEntity

@Dao
interface PendingAttachmentDao {

    @Upsert
    suspend fun upsertPendingAttachment(pendingAttachment: PendingAttachmentEntity)

    @Upsert
    suspend fun upsertPendingAttachments(pendingAttachments: List<PendingAttachmentEntity>)

    @Query("SELECT * FROM pendingattachmententity WHERE attachmentId = :attachmentId")
    suspend fun getPendingAttachmentById(attachmentId: String): PendingAttachmentEntity?

    @Query(
        """
        SELECT pending.* FROM pendingattachmententity AS pending
        INNER JOIN chatmessageentity AS msg ON pending.messageId = msg.messageId
        WHERE msg.chatId = :chatId
        """
    )
    suspend fun getPendingAttachmentsForChat(chatId: String): List<PendingAttachmentEntity>

    @Query("DELETE FROM pendingattachmententity WHERE attachmentId = :attachmentId")
    suspend fun deleteByAttachmentId(attachmentId: String)
}
