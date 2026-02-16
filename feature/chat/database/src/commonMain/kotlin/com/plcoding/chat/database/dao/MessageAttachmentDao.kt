package com.plcoding.chat.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.MessageAttachmentEntity

@Dao
interface MessageAttachmentDao {
    @Upsert
    suspend fun upsertAttachments(attachments: List<MessageAttachmentEntity>)

    @Query("SELECT * FROM messageattachmententity WHERE messageId = :messageId")
    suspend fun getAttachmentsByMessageId(messageId: String): List<MessageAttachmentEntity>

    @Query(
        """
        SELECT DISTINCT url FROM messageattachmententity a
        INNER JOIN chatmessageentity m ON a.messageId = m.messageId
        WHERE m.chatId = :chatId AND a.type LIKE 'audio/%'
    """,
    )
    suspend fun getAudioUrlsByChatId(chatId: String): List<String>

    @Query("UPDATE messageattachmententity SET url = :url, status = :status WHERE id = :attachmentId")
    suspend fun updateAttachmentUrlAndStatus(attachmentId: String, url: String, status: AttachmentUploadStatus)

    @Query("DELETE FROM messageattachmententity WHERE id IN (:ids)")
    suspend fun deleteAttachmentsByIds(ids: List<String>)

    @Transaction
    suspend fun upsertAttachmentsAndSync(
        messageId: String,
        serverAttachments: List<MessageAttachmentEntity>
    ) {
        val localAttachments = getAttachmentsByMessageId(messageId)
        upsertAttachments(serverAttachments)

        val serverAttachmentIds = serverAttachments.map { it.id }.toSet()
        val serverAttachmentsContent = serverAttachments.map { it.url to it.messageId }.toSet()

        val attachmentsToDelete = localAttachments.filter { localAttachment ->
            val isExactMatch = localAttachment.id in serverAttachmentIds
            val isContentMatch =
                (localAttachment.url to localAttachment.messageId) in serverAttachmentsContent
            when {
                isExactMatch -> false
                isContentMatch -> true
                else -> localAttachment.status == AttachmentUploadStatus.UPLOADED
            }
        }

        deleteAttachmentsByIds(attachmentsToDelete.map { it.id })
    }

    @Transaction
    suspend fun updateUploadedAttachment(
        attachmentId: String,
        url: String,
        pendingAttachmentDao: PendingAttachmentDao
    ) {
        updateAttachmentUrlAndStatus(attachmentId, url, AttachmentUploadStatus.UPLOADED)
        pendingAttachmentDao.deleteByAttachmentId(attachmentId)
    }
}
