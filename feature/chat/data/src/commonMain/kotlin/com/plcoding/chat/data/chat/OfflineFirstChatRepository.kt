package com.plcoding.chat.data.chat

import com.plcoding.chat.data.mappers.toChat
import com.plcoding.chat.data.mappers.toChatEntity
import com.plcoding.chat.data.mappers.toChatInfo
import com.plcoding.chat.data.mappers.toChatParticipant
import com.plcoding.chat.data.mappers.toChatParticipantEntity
import com.plcoding.chat.data.mappers.toDomainChatEventWithUsers
import com.plcoding.chat.data.mappers.toEntity
import com.plcoding.chat.data.mappers.toLastMessageView
import com.plcoding.chat.data.mappers.toMessageAttachment
import com.plcoding.chat.data.mappers.toMessageAttachmentEntity
import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.database.entities.ChatInfoEntity
import com.plcoding.chat.database.entities.ChatParticipantEntity
import com.plcoding.chat.database.entities.ChatWithParticipants
import com.plcoding.chat.domain.audio.AudioMetadata
import com.plcoding.chat.domain.chat.ChatRepository
import com.plcoding.chat.domain.chat.ChatService
import com.plcoding.chat.domain.models.Chat
import com.plcoding.chat.domain.models.ChatInfo
import com.plcoding.chat.domain.models.ChatParticipant
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.asEmptyResult
import com.plcoding.core.domain.util.onSuccess
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.supervisorScope

class OfflineFirstChatRepository(
    private val chatService: ChatService,
    private val db: ChirpChatDatabase,
    private val audioFileCache: AudioFileCache,
    private val audioMetadataExtractor: AudioMetadataExtractor,
) : ChatRepository {

    override fun getChats(): Flow<List<Chat>> {
        return db.chatDao.getChatsWithParticipants()
            .map { allChatsWithParticipants ->
                supervisorScope {
                    allChatsWithParticipants
                        .map { chatWithParticipants ->
                            async {
                                val activeParticipants = chatWithParticipants
                                    .participants
                                    .onlyActive(chatWithParticipants.chat.chatId)
                                    .map { it.toChatParticipant() }

                                val attachmentsOfLastMessage = chatWithParticipants
                                    .lastMessage
                                    ?.messageId
                                    ?.let { db.messageAttachmentDao.getAttachmentsByMessageId(it) }
                                    ?.map { it.toMessageAttachment() }
                                    .orEmpty()

                                chatWithParticipants
                                    .toChat(attachments = attachmentsOfLastMessage)
                                    .copy(participants = activeParticipants)
                            }
                        }
                        .awaitAll()
                }
            }
    }

    override fun getChatInfoById(chatId: String): Flow<ChatInfo> {
        return combine(
            db.chatDao.getChatInfoById(chatId).filterNotNull(),
            db.chatEventDao.getEventsWithUsersByChatId(chatId)
        ) { chatInfo, eventsWithUsers ->
            val filteredChatInfo = ChatInfoEntity(
                chat = chatInfo.chat,
                participants = chatInfo
                    .participants
                    .onlyActive(chatInfo.chat.chatId),
                messagesWithSenders = chatInfo.messagesWithSenders
            )
            val events = eventsWithUsers.map { it.toDomainChatEventWithUsers() }
            filteredChatInfo.toChatInfo().copy(events = events)
        }
    }

    override fun getActiveParticipantsByChatId(chatId: String): Flow<List<ChatParticipant>> {
        return db.chatDao.getActiveParticipantsByChatId(chatId)
            .map { participants ->
                participants.map { it.toChatParticipant() }
            }
    }

    override suspend fun fetchChats(): Result<List<Chat>, DataError.Remote> {
        return chatService
            .getChats()
            .onSuccess { chats ->
                val chatsWithParticipants = chats.map { chat ->
                    ChatWithParticipants(
                        chat = chat.toChatEntity(),
                        participants = chat.participants.map { it.toChatParticipantEntity() },
                        lastMessage = chat.lastMessage?.toLastMessageView()
                    )
                }

                db.chatDao.upsertChatsWithParticipantsAndCrossRefs(
                    chats = chatsWithParticipants,
                    participantDao = db.chatParticipantDao,
                    crossRefDao = db.chatParticipantsCrossRefDao,
                    messageDao = db.chatMessageDao
                )

                supervisorScope {
                    chats.map { chat ->
                        async {
                            val lastMessage = chat.lastMessage ?: return@async
                            if (lastMessage.attachments.isNotEmpty()) {
                                val attachmentEntities = lastMessage.attachments.map { attachment ->
                                    attachment.toMessageAttachmentEntity(lastMessage.id)
                                }
                                db.messageAttachmentDao.upsertAttachments(attachmentEntities)

                                val audioAttachments = lastMessage.attachments.filter {
                                    it.type == MessageAttachmentType.AUDIO
                                }
                                if (audioAttachments.isNotEmpty()) {
                                    val audioMetadataEntities = audioAttachments.map { attachment ->
                                        val durationMs =
                                            audioMetadataExtractor.extractDurationMs(attachment.url)
                                        val amplitudes =
                                            audioMetadataExtractor.extractAmplitudes(attachment.url)
                                        AudioMetadata(
                                            attachmentId = attachment.id,
                                            durationMs = durationMs,
                                            amplitudes = amplitudes,
                                        ).toEntity()
                                    }
                                    db.audioMetadataDao.upsertAudioMetadataAndSync(
                                        messageId = lastMessage.id,
                                        serverAudioMetadata = audioMetadataEntities
                                    )
                                }
                            }
                        }
                    }.awaitAll()
                }
            }
    }

    override suspend fun fetchChatById(chatId: String): EmptyResult<DataError.Remote> {
        return chatService
            .getChatById(chatId)
            .onSuccess { chat ->
                db.chatDao.upsertChatWithParticipantsAndCrossRefs(
                    chat = chat.toChatEntity(),
                    participants = chat.participants.map { it.toChatParticipantEntity() },
                    participantDao = db.chatParticipantDao,
                    crossRefDao = db.chatParticipantsCrossRefDao
                )
            }
            .asEmptyResult()
    }

    override suspend fun createChat(otherUserIds: List<String>): Result<Chat, DataError.Remote> {
        return chatService
            .createChat(otherUserIds)
            .onSuccess { chat ->
                db.chatDao.upsertChatWithParticipantsAndCrossRefs(
                    chat = chat.toChatEntity(),
                    participants = chat.participants.map { it.toChatParticipantEntity() },
                    participantDao = db.chatParticipantDao,
                    crossRefDao = db.chatParticipantsCrossRefDao,
                )
            }
    }

    override suspend fun leaveChat(
        chatId: String,
        confirmDelete: Boolean
    ): EmptyResult<DataError.Remote> {
        val audioUrls = db.messageAttachmentDao.getAudioUrlsByChatId(chatId)

        return chatService
            .leaveChat(chatId, confirmDelete)
            .onSuccess {
                if (audioUrls.isNotEmpty()) {
                    audioFileCache.deleteFilesByUrls(audioUrls)
                }
                db.chatDao.deleteChatById(chatId)
            }
    }

    override suspend fun removeParticipant(
        chatId: String,
        userId: String
    ): EmptyResult<DataError.Remote> {
        return chatService
            .removeParticipant(chatId, userId)
            .onSuccess {
                fetchChatById(chatId)
            }
    }

    override suspend fun addParticipantsToChat(
        chatId: String,
        userIds: List<String>
    ): Result<Chat, DataError.Remote> {
        return chatService
            .addParticipantsToChat(chatId, userIds)
            .onSuccess { chat ->
                db.chatDao.upsertChatWithParticipantsAndCrossRefs(
                    chat = chat.toChatEntity(),
                    participants = chat.participants.map { it.toChatParticipantEntity() },
                    participantDao = db.chatParticipantDao,
                    crossRefDao = db.chatParticipantsCrossRefDao,
                )
            }
    }

    override suspend fun deleteAllChats() {
        db.chatDao.deleteAllChats()
    }

    private suspend fun List<ChatParticipantEntity>.onlyActive(chatId: String): List<ChatParticipantEntity> {
        val activeParticipantIds = db
            .chatDao
            .getActiveParticipantsByChatId(chatId)
            .first()
            .map { it.userId }

        return this.filter { it.userId in activeParticipantIds }
    }
}
