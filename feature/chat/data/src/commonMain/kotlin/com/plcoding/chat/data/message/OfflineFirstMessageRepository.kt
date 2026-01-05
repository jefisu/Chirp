@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.data.message

import com.plcoding.chat.data.dto.websocket.OutgoingWebSocketDto
import com.plcoding.chat.data.dto.websocket.WebSocketMessageDto
import com.plcoding.chat.data.mappers.toChatMessageEntity
import com.plcoding.chat.data.mappers.toMessageAttachmentDto
import com.plcoding.chat.data.mappers.toMessageAttachmentEntity
import com.plcoding.chat.data.mappers.toMessageAttachmentsEntity
import com.plcoding.chat.data.mappers.toMessageWithSender
import com.plcoding.chat.data.mappers.toPendingAttachmentEntity
import com.plcoding.chat.data.network.KtorWebSocketConnector
import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.ChatMessageEntity
import com.plcoding.chat.domain.message.ChatMessageService
import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.message.MessageRepository
import com.plcoding.chat.domain.models.BackgroundUploadInfo
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.chat.domain.models.MessageWithSender
import com.plcoding.chat.domain.models.OutgoingNewMessage
import com.plcoding.chat.domain.models.PendingAttachment
import com.plcoding.core.data.database.safeDatabaseUpdate
import com.plcoding.core.domain.auth.SessionStorage
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.uuid.ExperimentalUuidApi

class OfflineFirstMessageRepository(
    private val database: ChirpChatDatabase,
    private val chatMessageService: ChatMessageService,
    private val sessionStorage: SessionStorage,
    private val json: Json,
    private val webSocketConnector: KtorWebSocketConnector,
    private val applicationScope: CoroutineScope,
    private val messageAttachmentRepository: MessageAttachmentRepository,
    private val messageAttachmentScheduler: MessageAttachmentScheduler,
    private val logger: ChirpLogger
) : MessageRepository {

    override suspend fun sendMessage(message: OutgoingNewMessage): Result<List<PendingAttachment>, DataError> {
        return safeDatabaseUpdate {
            val localUser = sessionStorage.observeAuthInfo().first()?.user
                ?: return Result.Failure(DataError.Local.NOT_FOUND)

            val entity = ChatMessageEntity(
                messageId = message.messageId,
                chatId = message.chatId,
                senderId = localUser.id,
                content = message.content,
                timestamp = Clock.System.now().toEpochMilliseconds(),
                deliveryStatus = ChatMessageDeliveryStatus.SENDING.name
            )

            val pendingAttachments = messageAttachmentRepository.storeLocalAttachments(
                chatId = message.chatId,
                messageId = message.messageId,
                files = message.media
            )

            val attachmentEntities = pendingAttachments.map {
                it.messageAttachment.toMessageAttachmentEntity(message.messageId)
            }

            val pendingAttachmentEntities = pendingAttachments.map {
                it.toPendingAttachmentEntity(message.messageId)
            }

            database.chatMessageDao.saveMessageLocally(
                message = entity,
                attachments = attachmentEntities,
                pendingAttachments = pendingAttachmentEntities,
                messageAttachmentDao = database.messageAttachmentDao,
                pendingAttachmentDao = database.pendingAttachmentDao
            )

            applicationScope.launch {
                initiateMessageUpload(message.chatId, pendingAttachments)
            }

            pendingAttachments
        }
    }

    override suspend fun retryMessage(messageId: String): EmptyResult<DataError> {
        return safeDatabaseUpdate {
            logger.info("Message ID retry $messageId")
            val messageWithSender = database.chatMessageDao.getMessageById(messageId)
                ?: return Result.Failure(DataError.Local.NOT_FOUND)

            val attachments = messageWithSender.attachments
            val failedAttachments =
                attachments.filter { it.status == AttachmentUploadStatus.FAILED }

            failedAttachments.forEach { attachment ->
                database.messageAttachmentDao.updateAttachmentUrlAndStatus(
                    attachmentId = attachment.id,
                    url = attachment.url,
                    status = AttachmentUploadStatus.UPLOADING
                )
            }

            database.chatMessageDao.updateDeliveryStatus(
                messageId = messageId,
                timestamp = Clock.System.now().toEpochMilliseconds(),
                status = ChatMessageDeliveryStatus.SENDING.name
            )

            if (failedAttachments.isNotEmpty()) {
                failedAttachments.forEach { attachment ->
                    messageAttachmentRepository
                        .retryAttachmentUpload(attachment.id)
                        .onSuccess { pending ->
                            messageAttachmentScheduler.scheduleUpload(
                                BackgroundUploadInfo(
                                    fileId = pending.messageAttachment.id,
                                    uploadUrl = pending.uploadUrl,
                                    localFilePath = pending.messageAttachment.url
                                )
                            )
                        }
                }
            }

            Result.Success(Unit)
        }
    }

    override suspend fun deleteMessage(messageId: String): EmptyResult<DataError> {
        val messageWithSender = database.chatMessageDao.getMessageById(messageId)

        if (
            messageWithSender != null
            && messageWithSender.message.deliveryStatus != ChatMessageDeliveryStatus.SENT.name
        ) {
            return safeDatabaseUpdate {
                messageWithSender.attachments.forEach { attachment ->
                    messageAttachmentScheduler.cancel(attachment.id)
                    messageAttachmentRepository.deleteAttachment(attachment.id)
                }
                database.chatMessageDao.deleteMessageById(messageId)
                Result.Success(Unit)
            }
        }

        return chatMessageService
            .deleteMessage(messageId)
            .onSuccess {
                applicationScope.launch {
                    database.chatMessageDao.deleteMessageById(messageId)
                }.join()
            }
    }

    override suspend fun updateMessageDeliveryStatus(
        messageId: String,
        status: ChatMessageDeliveryStatus
    ): EmptyResult<DataError.Local> {
        return safeDatabaseUpdate {
            database.chatMessageDao.updateDeliveryStatus(
                messageId = messageId,
                status = status.name,
                timestamp = Clock.System.now().toEpochMilliseconds()
            )
        }
    }

    override suspend fun fetchMessages(
        chatId: String,
        before: String?
    ): Result<List<ChatMessage>, DataError> {
        return chatMessageService
            .fetchMessages(chatId, before)
            .onSuccess { messages ->
                applicationScope.launch {
                    safeDatabaseUpdate {
                        saveFetchedMessages(
                            chatId = chatId,
                            messages = messages,
                            shouldSync = before == null // Only sync for most recent page
                        )
                    }
                }
            }
    }

    override fun getMessagesForChat(chatId: String): Flow<List<MessageWithSender>> {
        return database
            .chatMessageDao
            .getMessagesByChatId(chatId)
            .onEach { messages ->
                val sendingMessagesDomain = messages
                    .filter {
                        it.message.deliveryStatus == ChatMessageDeliveryStatus.SENDING.name
                    }
                    .map { it.toMessageWithSender() }

                processSendingMessages(sendingMessagesDomain)
            }
            .map { messages ->
                messages.map { it.toMessageWithSender() }
            }
    }

    private suspend fun initiateMessageUpload(
        chatId: String,
        attachments: List<PendingAttachment>
    ) {
        if (attachments.isEmpty()) {
            return
        }

        val uploadInfoResult = messageAttachmentRepository
            .fetchUploadInfo(chatId, attachments)
            .onFailure {
                return
            }

        val updatedAttachments = (uploadInfoResult as Result.Success).data

        for (attachment in updatedAttachments) {
            val pendingEntity = database
                .pendingAttachmentDao
                .getPendingAttachmentById(attachment.messageAttachment.id)
                ?: continue
            database.pendingAttachmentDao.upsertPendingAttachment(
                pendingEntity.copy(
                    uploadUrl = attachment.uploadUrl,
                    expiresAt = attachment.uploadExpiresAt.toEpochMilliseconds(),
                    publicUrl = attachment.publicUrl
                )
            )
        }

        updatedAttachments.forEach { attachment ->
            messageAttachmentScheduler.scheduleUpload(
                BackgroundUploadInfo(
                    fileId = attachment.messageAttachment.id,
                    uploadUrl = attachment.uploadUrl,
                    localFilePath = attachment.messageAttachment.url
                )
            )
        }
    }

    private suspend fun processSendingMessages(sendingMessages: List<MessageWithSender>) {
        if (sendingMessages.isEmpty()) return

        for (messageWithSender in sendingMessages) {
            val attachments = messageWithSender.message.attachments
            val allUploaded = attachments.all {
                it.status == MessageAttachmentUploadStatus.UPLOADED
            }

            if (!allUploaded) {
                val anyFailed = attachments.any {
                    it.status == MessageAttachmentUploadStatus.FAILED
                }
                if (anyFailed) {
                    database.chatMessageDao.updateDeliveryStatus(
                        messageId = messageWithSender.message.id,
                        timestamp = Clock.System.now().toEpochMilliseconds(),
                        status = ChatMessageDeliveryStatus.FAILED.name
                    )
                }
                continue
            }

            val outgoingNewMessage = OutgoingWebSocketDto.NewMessage(
                chatId = messageWithSender.message.chatId,
                messageId = messageWithSender.message.id,
                content = messageWithSender.message.content,
                attachments = attachments.map { it.toMessageAttachmentDto() }
            )

            webSocketConnector
                .sendMessage(outgoingNewMessage.toJsonPayload())
                .onSuccess {
                    database.chatMessageDao.updateDeliveryStatus(
                        messageId = messageWithSender.message.id,
                        timestamp = Clock.System.now().toEpochMilliseconds(),
                        status = ChatMessageDeliveryStatus.SENT.name
                    )
                }
                .onFailure {
                    database.chatMessageDao.updateDeliveryStatus(
                        messageId = messageWithSender.message.id,
                        timestamp = Clock.System.now().toEpochMilliseconds(),
                        status = ChatMessageDeliveryStatus.FAILED.name
                    )
                }
        }
    }

    private suspend fun saveFetchedMessages(
        chatId: String,
        messages: List<ChatMessage>,
        shouldSync: Boolean
    ) {
        val serverMessages = messages.map { it.toChatMessageEntity() }
        val allServerAttachments = messages.flatMap {
            it.toMessageAttachmentsEntity(status = AttachmentUploadStatus.UPLOADED)
        }

        database.chatMessageDao.saveFetchedMessages(
            chatId = chatId,
            serverMessages = serverMessages,
            allServerAttachments = allServerAttachments,
            pageSize = ChatMessageConstants.PAGE_SIZE,
            shouldSync = shouldSync,
            messageAttachmentDao = database.messageAttachmentDao
        )
    }

    private fun OutgoingWebSocketDto.NewMessage.toJsonPayload(): String {
        val payloadJson = json
            .encodeToJsonElement(this)
            .jsonObject
            .toMutableMap()
            .apply {
                remove("type")
            }
        val webSocketMessage = WebSocketMessageDto(
            type = type.name,
            payload = json.encodeToString(JsonObject(payloadJson))
        )
        return json.encodeToString(webSocketMessage)
    }
}
