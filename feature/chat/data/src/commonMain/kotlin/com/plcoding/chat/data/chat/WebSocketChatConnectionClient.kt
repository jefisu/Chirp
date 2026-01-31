package com.plcoding.chat.data.chat

import com.plcoding.chat.data.dto.websocket.IncomingWebSocketDto
import com.plcoding.chat.data.dto.websocket.IncomingWebSocketType
import com.plcoding.chat.data.dto.websocket.OutgoingWebSocketDto
import com.plcoding.chat.data.dto.websocket.WebSocketMessageDto
import com.plcoding.chat.data.mappers.toChatEventEntity
import com.plcoding.chat.data.mappers.toChatMessage
import com.plcoding.chat.data.mappers.toChatMessageEntity
import com.plcoding.chat.data.mappers.toDomainChatEventWithUsers
import com.plcoding.chat.data.mappers.toMessageAttachmentsEntities
import com.plcoding.chat.data.mappers.toTypingEvent
import com.plcoding.chat.data.mappers.wrapOutgoingMessage
import com.plcoding.chat.data.network.KtorWebSocketConnector
import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.domain.chat.ChatConnectionClient
import com.plcoding.chat.domain.chat.ChatDeletedEvent
import com.plcoding.chat.domain.chat.ChatRepository
import com.plcoding.chat.domain.chat.RemovedFromChatEvent
import com.plcoding.core.domain.auth.SessionStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.shareIn
import kotlinx.serialization.json.Json

class WebSocketChatConnectionClient(
    private val webSocketConnector: KtorWebSocketConnector,
    private val chatRepository: ChatRepository,
    private val database: ChirpChatDatabase,
    private val sessionStorage: SessionStorage,
    private val json: Json,
    private val applicationScope: CoroutineScope
) : ChatConnectionClient {

    override val chatMessages = incomingMessages<IncomingWebSocketDto.NewMessageDto, _> {
        database.chatMessageDao.getMessageById(it.id)?.toChatMessage()
    }

    override val connectionState = webSocketConnector.connectionState

    override val typingEvents = incomingMessages<IncomingWebSocketDto.TypingEventDto, _> {
        it.toTypingEvent()
    }

    override val chatEvents = incomingMessages<IncomingWebSocketDto.ChatEventDto, _> {
        database.chatEventDao.getEventWithUsersById(it.eventId)?.toDomainChatEventWithUsers()
    }

    override val chatDeletedEvents = incomingMessages<IncomingWebSocketDto.ChatDeletedDto, _> {
        ChatDeletedEvent(it.chatId, it.deletedByUserId)
    }

    override val removedFromChatEvents =
        incomingMessages<IncomingWebSocketDto.RemovedFromChatDto, _> {
            RemovedFromChatEvent(it.chatId, it.removedByUserId, it.removedByUsername)
        }

    private inline fun <reified T : IncomingWebSocketDto, R : Any> incomingMessages(
        crossinline transform: suspend (T) -> R?
    ): Flow<R> {
        return webSocketConnector
            .messages
            .mapNotNull { parseIncomingMessage(it) }
            .onEach { handleIncomingMessage(it) }
            .filterIsInstance<T>()
            .mapNotNull { transform(it) }
            .shareIn(
                applicationScope,
                SharingStarted.WhileSubscribed(5000)
            )
    }

    override suspend fun sendTypingEvent(chatId: String, isTyping: Boolean) {
        val dto = OutgoingWebSocketDto.TypingEvent(
            chatId = chatId,
            isTyping = isTyping
        )
        webSocketConnector.sendMessage(json.wrapOutgoingMessage(dto))
    }

    private fun parseIncomingMessage(message: WebSocketMessageDto): IncomingWebSocketDto? {
        return when (message.type) {
            IncomingWebSocketType.NEW_MESSAGE.name -> {
                json.decodeFromString<IncomingWebSocketDto.NewMessageDto>(message.payload)
            }

            IncomingWebSocketType.MESSAGE_DELETED.name -> {
                json.decodeFromString<IncomingWebSocketDto.MessageDeletedDto>(message.payload)
            }

            IncomingWebSocketType.PROFILE_PICTURE_UPDATED.name -> {
                json.decodeFromString<IncomingWebSocketDto.ProfilePictureUpdated>(message.payload)
            }

            IncomingWebSocketType.CHAT_PARTICIPANTS_CHANGED.name -> {
                json.decodeFromString<IncomingWebSocketDto.ChatParticipantsChangedDto>(message.payload)
            }

            IncomingWebSocketType.TYPING_EVENT.name -> {
                json.decodeFromString<IncomingWebSocketDto.TypingEventDto>(message.payload)
            }

            IncomingWebSocketType.CHAT_EVENT.name -> {
                json.decodeFromString<IncomingWebSocketDto.ChatEventDto>(message.payload)
            }

            IncomingWebSocketType.CHAT_DELETED.name -> {
                json.decodeFromString<IncomingWebSocketDto.ChatDeletedDto>(message.payload)
            }

            IncomingWebSocketType.REMOVED_FROM_CHAT.name -> {
                json.decodeFromString<IncomingWebSocketDto.RemovedFromChatDto>(message.payload)
            }

            else -> null
        }
    }

    private suspend fun handleIncomingMessage(message: IncomingWebSocketDto) {
        when (message) {
            is IncomingWebSocketDto.ChatParticipantsChangedDto -> refreshChat(message)
            is IncomingWebSocketDto.MessageDeletedDto -> deleteMessage(message)
            is IncomingWebSocketDto.NewMessageDto -> handleNewMessage(message)
            is IncomingWebSocketDto.ProfilePictureUpdated -> updateProfilePicture(message)
            is IncomingWebSocketDto.TypingEventDto -> Unit
            is IncomingWebSocketDto.ChatEventDto -> handleChatEvent(message)
            is IncomingWebSocketDto.ChatDeletedDto -> handleChatDeleted(message)
            is IncomingWebSocketDto.RemovedFromChatDto -> handleRemovedFromChat(message)
        }
    }

    private suspend fun refreshChat(message: IncomingWebSocketDto.ChatParticipantsChangedDto) {
        chatRepository.fetchChatById(message.chatId)
    }

    private suspend fun deleteMessage(message: IncomingWebSocketDto.MessageDeletedDto) {
        database.chatMessageDao.deleteMessageById(message.messageId)
    }

    private suspend fun handleNewMessage(message: IncomingWebSocketDto.NewMessageDto) {
        val chatExists = database.chatDao.getChatById(message.chatId) != null
        if (!chatExists) {
            chatRepository.fetchChatById(message.chatId)
        }

        val entity = message.toChatMessageEntity()
        val serverAttachments = message.toMessageAttachmentsEntities()

        database.chatMessageDao.saveFetchedMessages(
            chatId = message.chatId,
            serverMessages = listOf(entity),
            allServerAttachments = serverAttachments,
            pageSize = 1,
            shouldSync = false,
            messageAttachmentDao = database.messageAttachmentDao
        )
    }

    private suspend fun updateProfilePicture(message: IncomingWebSocketDto.ProfilePictureUpdated) {
        database.chatParticipantDao.updateProfilePictureUrl(
            userId = message.userId,
            newUrl = message.newUrl
        )

        val authInfo = sessionStorage.observeAuthInfo().firstOrNull()
        if (authInfo != null && authInfo.user.id == message.userId) {
            sessionStorage.set(
                info = authInfo.copy(
                    user = authInfo.user.copy(
                        profilePictureUrl = message.newUrl
                    )
                )
            )
        }
    }

    private suspend fun handleChatEvent(message: IncomingWebSocketDto.ChatEventDto) {
        val entity = message.toChatEventEntity()
        database.chatEventDao.upsertEvent(entity)
        chatRepository.fetchChatById(message.chatId)
    }

    private suspend fun handleChatDeleted(message: IncomingWebSocketDto.ChatDeletedDto) {
        database.chatDao.deleteChatById(message.chatId)
    }

    private suspend fun handleRemovedFromChat(message: IncomingWebSocketDto.RemovedFromChatDto) {
        database.chatDao.deleteChatById(message.chatId)
    }
}
