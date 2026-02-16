@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.data.message

import com.plcoding.chat.data.dto.websocket.OutgoingWebSocketDto
import com.plcoding.chat.data.mappers.toChatEventEntity
import com.plcoding.chat.data.mappers.toChatMessageEntity
import com.plcoding.chat.data.mappers.toEntity
import com.plcoding.chat.data.mappers.toMessageAttachmentDto
import com.plcoding.chat.data.mappers.toMessageAttachmentEntity
import com.plcoding.chat.data.mappers.toMessageAttachmentsEntity
import com.plcoding.chat.data.mappers.toMessageWithSender
import com.plcoding.chat.data.mappers.toPendingAttachmentEntity
import com.plcoding.chat.data.mappers.wrapOutgoingMessage
import com.plcoding.chat.data.network.KtorWebSocketConnector
import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.ChatMessageEntity
import com.plcoding.chat.database.entities.MessageAttachmentEntity
import com.plcoding.chat.domain.audio.AudioMetadata
import com.plcoding.chat.domain.audio.AudioMetadataRepository
import com.plcoding.chat.domain.message.ChatMessageService
import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.message.MessageRepository
import com.plcoding.chat.domain.models.BackgroundUploadInfo
import com.plcoding.chat.domain.models.ChatHistoryItem
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.chat.domain.models.MessageWithSender
import com.plcoding.chat.domain.models.OutgoingNewMessage
import com.plcoding.chat.domain.models.PendingAttachment
import com.plcoding.core.data.database.safeDatabaseUpdate
import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.auth.SessionStorage
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.serialization.json.Json
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
    private val logger: ChirpLogger,
    private val audioFileCache: AudioFileCache,
    private val audioMetadataExtractor: AudioMetadataExtractor,
    private val audioMetadataRepository: AudioMetadataRepository,
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
                pendingAttachmentDao = database.pendingAttachmentDao,
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
        val audioAttachmentUrls = messageWithSender
            ?.attachments
            ?.filter { it.type.startsWith("audio/") }
            ?.map { it.url }
            ?: emptyList()

        if (audioAttachmentUrls.isNotEmpty()) {
            audioFileCache.deleteFilesByUrls(audioAttachmentUrls)
        }

        if (
            messageWithSender != null &&
            messageWithSender.message.deliveryStatus != ChatMessageDeliveryStatus.SENT.name
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

    override suspend fun fetchHistory(
        chatId: String,
        before: String?
    ): Result<List<ChatHistoryItem>, DataError> {
        return chatMessageService
            .fetchHistory(chatId, before)
            .onSuccess { items ->
                applicationScope.launch {
                    safeDatabaseUpdate {
                        saveFetchedHistory(
                            chatId = chatId,
                            items = items,
                            shouldSync = before == null
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
                .sendMessage(json.wrapOutgoingMessage(outgoingNewMessage))
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

        val audioMetadataList = allServerAttachments.filter {
            it.type == MessageAttachmentType.AUDIO.name
        }
        saveFetchedAudiosAttachment(audioMetadataList)

        database.chatMessageDao.saveFetchedMessages(
            chatId = chatId,
            serverMessages = serverMessages,
            allServerAttachments = allServerAttachments,
            pageSize = ChatMessageConstants.PAGE_SIZE,
            shouldSync = shouldSync,
            messageAttachmentDao = database.messageAttachmentDao
        )
    }

    private suspend fun saveFetchedHistory(
        chatId: String,
        items: List<ChatHistoryItem>,
        shouldSync: Boolean
    ) {
        val messages = items.filterIsInstance<ChatHistoryItem.Message>().map { it.message }
        val events = items.filterIsInstance<ChatHistoryItem.Event>().map { it.event }

        if (messages.isNotEmpty()) {
            saveFetchedMessages(chatId, messages, shouldSync)
        }

        if (events.isNotEmpty()) {
            val eventEntities = events.map { it.toChatEventEntity() }
            database.chatEventDao.upsertEvents(eventEntities)
        }
    }

    private suspend fun saveFetchedAudiosAttachment(
        allServerAudios: List<MessageAttachmentEntity>
    ) {
        if (allServerAudios.isEmpty()) return
        if (allServerAudios.all { it.type != MessageAttachmentType.AUDIO.name }) return

        val audioMetadataEntities = supervisorScope {
            allServerAudios.map {
                async {
                    val url = it.url
                    AudioMetadata(
                        attachmentId = it.id,
                        durationMs = audioMetadataExtractor.extractDurationMs(url),
                        amplitudes = audioMetadataExtractor.extractAmplitudes(url)
                    ).toEntity()
                }
            }
        }.awaitAll()
        database.audioMetadataDao.upsertAll(audioMetadataEntities)
    }
}
