package com.plcoding.chat.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import com.plcoding.chat.database.entities.ChatMessageEntity
import com.plcoding.chat.database.entities.MessageAttachmentEntity
import com.plcoding.chat.database.entities.MessageWithSender
import com.plcoding.chat.database.entities.PendingAttachmentEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

@Dao
interface ChatMessageDao {

    @Upsert
    suspend fun upsertMessage(message: ChatMessageEntity)

    @Upsert
    suspend fun upsertMessages(messages: List<ChatMessageEntity>)

    @Query("DELETE FROM chatmessageentity WHERE messageId = :messageId")
    suspend fun deleteMessageById(messageId: String)

    @Query("DELETE FROM chatmessageentity WHERE messageId IN (:messageIds)")
    suspend fun deleteMessagesById(messageIds: List<String>)

    @Query("SELECT * FROM chatmessageentity WHERE chatId = :chatId ORDER BY timestamp DESC")
    @Transaction
    fun getMessagesByChatId(chatId: String): Flow<List<MessageWithSender>>

    @Query("""
        SELECT *
        FROM chatmessageentity
        WHERE chatId = :chatId
        ORDER BY timestamp DESC
        LIMIT :limit
    """)
    fun getMessagesByChatIdLimited(chatId: String, limit: Int): Flow<List<ChatMessageEntity>>

    @Query("SELECT * FROM chatmessageentity WHERE messageId = :messageId")
    @Transaction
    suspend fun getMessageById(messageId: String): MessageWithSender?

    @Query("""
        UPDATE chatmessageentity
        SET deliveryStatus = :status, deliveryStatusTimestamp = :timestamp
        WHERE messageId = :messageId
    """)
    suspend fun updateDeliveryStatus(messageId: String, status: String, timestamp: Long)

    @Transaction
    suspend fun upsertMessagesAndSyncIfNecessary(
        chatId: String,
        serverMessages: List<ChatMessageEntity>,
        pageSize: Int,
        shouldSync: Boolean = false
    ) {
        val localMessages = getMessagesByChatIdLimited(
            chatId = chatId,
            limit = pageSize
        ).first()

        upsertMessages(serverMessages)

        if(!shouldSync) {
            return
        }

        val serverIds = serverMessages.map { it.messageId }.toSet()

        val messagesToDelete = localMessages.filter { localMessage ->
            val missingOnServer = localMessage.messageId !in serverIds
            val isSent = localMessage.deliveryStatus == "SENT"

            missingOnServer && isSent
        }

        val messageIds = messagesToDelete.map { it.messageId }
        deleteMessagesById(messageIds)
    }

    @Transaction
    suspend fun saveMessageLocally(
        message: ChatMessageEntity,
        attachments: List<MessageAttachmentEntity>,
        pendingAttachments: List<PendingAttachmentEntity>,
        messageAttachmentDao: MessageAttachmentDao,
        pendingAttachmentDao: PendingAttachmentDao
    ) {
        upsertMessage(message)
        messageAttachmentDao.upsertAttachments(attachments)
        pendingAttachmentDao.upsertPendingAttachments(pendingAttachments)
    }

    @Transaction
    suspend fun saveFetchedMessages(
        chatId: String,
        serverMessages: List<ChatMessageEntity>,
        allServerAttachments: List<MessageAttachmentEntity>,
        pageSize: Int,
        shouldSync: Boolean,
        messageAttachmentDao: MessageAttachmentDao
    ) {
        upsertMessagesAndSyncIfNecessary(
            chatId = chatId,
            serverMessages = serverMessages,
            pageSize = pageSize,
            shouldSync = shouldSync
        )

        val attachmentsByMessage = allServerAttachments.groupBy { it.messageId }

        serverMessages.forEach { message ->
            val serverAttachments = attachmentsByMessage[message.messageId] ?: emptyList()
            messageAttachmentDao.upsertAttachmentsAndSync(message.messageId, serverAttachments)
        }
    }
}
