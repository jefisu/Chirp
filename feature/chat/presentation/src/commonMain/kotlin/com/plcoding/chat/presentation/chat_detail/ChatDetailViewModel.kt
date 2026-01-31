@file:OptIn(ExperimentalCoroutinesApi::class, ExperimentalUuidApi::class)

package com.plcoding.chat.presentation.chat_detail

import androidx.compose.foundation.text.input.clearText
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.error_saving_image
import chirp.feature.chat.presentation.generated.resources.image_saved_successfully
import chirp.feature.chat.presentation.generated.resources.today
import com.plcoding.chat.domain.chat.ChatConnectionClient
import com.plcoding.chat.domain.chat.ChatRepository
import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageRepository
import com.plcoding.chat.domain.models.ChatHistoryItem
import com.plcoding.chat.domain.models.ConnectionState
import com.plcoding.chat.domain.models.OutgoingNewMessage
import com.plcoding.chat.presentation.chat_list_detail.ChatListDetailState
import com.plcoding.chat.presentation.mappers.toUi
import com.plcoding.chat.presentation.mappers.toUiListWithEvents
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.util.toFile
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.domain.auth.SessionStorage
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataErrorException
import com.plcoding.core.domain.util.Paginator
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.UiText
import com.plcoding.core.presentation.util.toUiText
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class ChatDetailViewModel(
    private val chatRepository: ChatRepository,
    private val sessionStorage: SessionStorage,
    private val messageRepository: MessageRepository,
    private val connectionClient: ChatConnectionClient,
    private val messageAttachmentRepository: MessageAttachmentRepository,
    private val sharedState: StateFlow<ChatListDetailState>
) : ViewModel() {

    private val eventChannel = Channel<ChatDetailEvent>()
    val events = eventChannel.receiveAsFlow()

    private val _chatId = MutableStateFlow<String?>(null)

    private var hasLoadedInitialData = false

    private var currentPaginator: Paginator<String?, ChatHistoryItem>? = null

    private val temporaryAttachmentFiles = MutableStateFlow(emptyMap<String, File>())

    private val chatInfoFlow = _chatId
        .onEach { chatId ->
            if (chatId != null) {
                setupPaginatorForChat(chatId)
                loadNextItems()
            } else {
                currentPaginator = null
                temporaryAttachmentFiles.update { emptyMap() }
            }
        }
        .flatMapLatest { chatId ->
            if (chatId != null) {
                chatRepository.getChatInfoById(chatId)
            } else emptyFlow()
        }

    private val _state = MutableStateFlow(ChatDetailState())

    private val canSendMessage = combine(
        snapshotFlow { _state.value.messageTextFieldState.text.toString() },
        _state.map { it.imagesSelected }.distinctUntilChanged(),
        connectionClient.connectionState
    ) { text, images, connectionState ->
        connectionState == ConnectionState.CONNECTED && (text.isNotBlank() || images.isNotEmpty())
    }


    private val stateWithMessages = combine(
        _state,
        chatInfoFlow,
        sessionStorage.observeAuthInfo(),
        temporaryAttachmentFiles,
        sharedState
    ) { currentState, chatInfo, authInfo, temporaryFiles, sharedState ->
        if (authInfo == null) {
            return@combine ChatDetailState()
        }

        val typingUsers = _chatId.value?.let { sharedState.typingUsersByChat[it] } ?: emptyMap()

        currentState.copy(
            chatUi = chatInfo.chat.toUi(authInfo.user.id),
            messages = toUiListWithEvents(
                localUserId = authInfo.user.id,
                messages = chatInfo.messages,
                events = chatInfo.events,
                temporaryAttachmentFiles = temporaryFiles
            ),
            typingUsers = typingUsers
        )
    }

    val state = _chatId
        .flatMapLatest { chatId ->
            if (chatId != null) {
                stateWithMessages
            } else {
                _state
            }
        }
        .onStart {
            if (!hasLoadedInitialData) {
                observeConnectionState()
                observeChatMessages()
                observeCanSendMessage()
                observeOwnTypingStatus()
                hasLoadedInitialData = true
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = ChatDetailState()
        )

    fun onAction(action: ChatDetailAction) {
        when (action) {
            is ChatDetailAction.OnSelectChat -> switchChat(action.chatId)
            ChatDetailAction.OnChatOptionsClick -> onChatOptionsClick()
            is ChatDetailAction.OnDeleteMessageClick -> deleteMessage(action.message)
            ChatDetailAction.OnDismissChatOptions -> onDismissChatOptions()
            ChatDetailAction.OnDismissMessageMenu -> onDismissMessageMenu()
            ChatDetailAction.OnLeaveChatClick -> onLeaveChatClick()
            is ChatDetailAction.OnMessageLongClick -> onMessageLongClick(action.message)
            is ChatDetailAction.OnRetryClick -> retryMessage(action.message)
            ChatDetailAction.OnScrollToTop -> onScrollToTop()
            ChatDetailAction.OnSendMessageClick -> sendMessage()
            ChatDetailAction.OnRetryPaginationClick -> retryPagination()
            ChatDetailAction.OnHideBanner -> hideBanner()
            is ChatDetailAction.OnTopVisibleIndexChanged -> updateBanner(action.topVisibleIndex)
            is ChatDetailAction.OnFirstVisibleIndexChanged -> updateNearBottom(action.index)
            is ChatDetailAction.OnImagesSelected -> updateImagesSelected(action.images)
            is ChatDetailAction.OnRemoveImageSelected -> removeImageSelected(action.image)
            ChatDetailAction.OnDismissErrorDialog -> dismissError()
            ChatDetailAction.OnDismissImagePreview -> dismissImagePreview()
            is ChatDetailAction.OnAttachmentClick -> showAttachmentPreview(action.data)
            is ChatDetailAction.OnAttachmentLongClick -> onAttachmentLongClick(action.attachment)
            ChatDetailAction.OnDismissAttachmentMenu -> onDismissAttachmentMenu()
            is ChatDetailAction.OnSaveAttachmentClick -> downloadAttachment(action.attachment)
            ChatDetailAction.OnConfirmAdminLeave -> confirmAdminLeave()
            ChatDetailAction.OnDismissAdminLeaveConfirmation -> dismissAdminLeaveConfirmation()
            is ChatDetailAction.OnRemoveMemberClick -> showRemoveMemberConfirmation(action.userId)
            ChatDetailAction.OnConfirmRemoveMember -> confirmRemoveMember()
            ChatDetailAction.OnDismissRemoveMemberConfirmation -> dismissRemoveMemberConfirmation()
            else -> Unit
        }
    }

    fun onEvent(event: ChatDetailEvent) {
        when (event) {
            is ChatDetailEvent.OnError -> showError(event.error)
            else -> Unit
        }
    }

    private fun downloadAttachment(attachment: MessageAttachmentUi) {
        onDismissAttachmentMenu()
        viewModelScope.launch {
            messageAttachmentRepository
                .downloadAttachment(attachment.url)
                .onSuccess {
                    eventChannel.send(ChatDetailEvent.OnError(UiText.Resource(Res.string.image_saved_successfully)))
                }
                .onFailure {
                    eventChannel.send(ChatDetailEvent.OnError(UiText.Resource(Res.string.error_saving_image)))
                }
        }
    }

    private fun onAttachmentLongClick(attachment: MessageAttachmentUi) {
        _state.update {
            it.copy(
                attachmentWithOpenMenu = attachment
            )
        }
    }

    private fun onDismissAttachmentMenu() {
        _state.update {
            it.copy(
                attachmentWithOpenMenu = null
            )
        }
    }

    private fun showAttachmentPreview(attachment: Any) {
        _state.update {
            it.copy(attachmentPreviewData = attachment)
        }
    }

    private fun dismissImagePreview() {
        _state.update {
            it.copy(attachmentPreviewData = null)
        }
    }

    private fun showError(error: UiText) {
        _state.update { it.copy(error = error) }
    }

    private fun dismissError() {
        _state.update { it.copy(error = null) }
    }

    private fun removeImageSelected(image: PickedImageData) {
        _state.update { it.copy(imagesSelected = it.imagesSelected - image) }
    }

    private fun updateImagesSelected(images: List<PickedImageData>) {
        _state.update {
            val maxItems = 10
            val updatedImages = it.imagesSelected +
                    images.filter { image -> !it.imagesSelected.contains(image) }
            it.copy(imagesSelected = updatedImages.take(maxItems))
        }
    }

    private fun updateNearBottom(firstVisibleIndex: Int) {
        _state.update {
            it.copy(
                isNearBottom = firstVisibleIndex <= 3
            )
        }
    }

    private fun updateBanner(topVisibleIndex: Int) {
        val visibleDate = calculateBannerDateFromIndex(
            messages = state.value.messages,
            index = topVisibleIndex
        )

        _state.update {
            it.copy(
                bannerState = BannerState(
                    formattedDate = visibleDate,
                    isVisible = visibleDate != null
                )
            )
        }
    }

    private fun calculateBannerDateFromIndex(
        messages: List<MessageUi>,
        index: Int
    ): UiText? {
        if (messages.isEmpty() || index < 0 || index >= messages.size) {
            return null
        }

        val nearestDateSeparator = (index until messages.size)
            .asSequence()
            .mapNotNull { index ->
                val item = messages.getOrNull(index)
                if (item is MessageUi.DateSeparator) item.date else null
            }
            .firstOrNull()

        return when (nearestDateSeparator) {
            is UiText.Resource -> {
                if (nearestDateSeparator.id == Res.string.today) null else nearestDateSeparator
            }

            else -> nearestDateSeparator
        }
    }

    private fun hideBanner() {
        _state.update {
            it.copy(
                bannerState = it.bannerState.copy(
                    isVisible = false
                )
            )
        }
    }

    private fun retryPagination() = loadNextItems()

    private fun onScrollToTop() = loadNextItems()

    private fun loadNextItems() {
        viewModelScope.launch {
            currentPaginator?.loadNextItems()
        }
    }

    private fun onDismissMessageMenu() {
        _state.update {
            it.copy(
                messageWithOpenMenu = null
            )
        }
    }

    private fun onMessageLongClick(message: MessageUi.LocalUserMessage) {
        _state.update {
            it.copy(
                messageWithOpenMenu = message
            )
        }
    }

    private fun deleteMessage(message: MessageUi.LocalUserMessage) {
        viewModelScope.launch {
            messageRepository
                .deleteMessage(message.id)
                .onFailure { error ->
                    eventChannel.send(ChatDetailEvent.OnError(error.toUiText()))
                }
        }
    }

    private fun retryMessage(message: MessageUi.LocalUserMessage) {
        viewModelScope.launch {
            messageRepository
                .retryMessage(message.id)
                .onFailure { error ->
                    eventChannel.send(ChatDetailEvent.OnError(error.toUiText()))
                }
        }
    }

    private fun sendMessage() {
        val currentChatId = _chatId.value
        val content = state.value.messageTextFieldState.text.toString().trim()
        val filesToUpload = _state.value.imagesSelected.map { it.toFile() }
        if (
            (content.isBlank() && filesToUpload.isEmpty())
            || currentChatId == null
        ) return

        viewModelScope.launch {
            connectionClient.sendTypingEvent(currentChatId, false)
            messageRepository
                .sendMessage(
                    OutgoingNewMessage(
                        chatId = currentChatId,
                        messageId = Uuid.random().toString(),
                        content = content.ifBlank { null },
                        media = filesToUpload
                    )
                )
                .onSuccess { attachments ->
                    state.value.messageTextFieldState.clearText()
                    _state.update { it.copy(imagesSelected = emptyList()) }
                    temporaryAttachmentFiles.update {
                        attachments.associate { it.messageAttachment.id to it.file }
                    }
                }
                .onFailure { error ->
                    eventChannel.send(ChatDetailEvent.OnError(error.toUiText()))
                }
        }
    }

    private fun observeCanSendMessage() {
        canSendMessage.onEach { canSend ->
            _state.update {
                it.copy(
                    canSendMessage = canSend
                )
            }
        }.launchIn(viewModelScope)
    }

    private fun observeChatMessages() {
        val currentMessages = state
            .map { it.messages }
            .distinctUntilChanged()

        val newMessages = _chatId.flatMapLatest { chatId ->
            if (chatId != null) {
                messageRepository.getMessagesForChat(chatId)
            } else emptyFlow()
        }

        val isNearBottom = state.map { it.isNearBottom }.distinctUntilChanged()

        combine(
            currentMessages,
            newMessages,
            isNearBottom
        ) { currentMessages, newMessages, isNearBottom ->
            val lastNewId = newMessages.lastOrNull()?.message?.id
            val lastCurrentId = currentMessages.lastOrNull()?.id

            if (lastNewId != lastCurrentId && isNearBottom) {
                eventChannel.send(ChatDetailEvent.OnNewMessage)
            }
        }.launchIn(viewModelScope)
    }

    private fun observeConnectionState() {
        connectionClient
            .connectionState
            .onEach { connectionState ->
                if (connectionState == ConnectionState.CONNECTED) {
                    currentPaginator?.loadNextItems()
                }

                _state.update {
                    it.copy(
                        connectionState = connectionState
                    )
                }
            }
            .launchIn(viewModelScope)
    }

    private fun observeOwnTypingStatus() {
        snapshotFlow { _state.value.messageTextFieldState.text.toString() }
            .onEach { text ->
                val chatId = _chatId.value ?: return@onEach
                if (text.isEmpty()) {
                    connectionClient.sendTypingEvent(chatId, false)
                } else {
                    connectionClient.sendTypingEvent(chatId, true)
                }
            }
            .launchIn(viewModelScope)
    }

    private fun setupPaginatorForChat(chatId: String) {
        currentPaginator = Paginator(
            initialKey = null,
            onLoadUpdated = { isLoading ->
                _state.update { it.copy(isPaginationLoading = isLoading) }
            },
            onRequest = { beforeTimestamp ->
                messageRepository.fetchHistory(chatId, beforeTimestamp)
            },
            getNextKey = { items ->
                items.minOfOrNull { it.createdAt }?.toString()
            },
            onError = { throwable ->
                if (throwable is DataErrorException) {
                    _state.update {
                        it.copy(
                            paginationError = throwable.error.toUiText()
                        )
                    }
                }
            },
            onSuccess = { items, _ ->
                _state.update {
                    it.copy(
                        endReached = items.isEmpty(),
                        paginationError = null
                    )
                }
            }
        )

        _state.update {
            it.copy(
                endReached = false,
                isPaginationLoading = false,
            )
        }
    }

    private fun onLeaveChatClick() {
        val chatUi = state.value.chatUi ?: return

        _state.update {
            it.copy(
                isChatOptionsOpen = false
            )
        }

        if (chatUi.isCurrentUserAdmin && chatUi.otherParticipants.isNotEmpty()) {
            _state.update {
                it.copy(isAdminLeaveConfirmationVisible = true)
            }
        } else {
            performLeaveChat(confirmDelete = false)
        }
    }

    private fun confirmAdminLeave() {
        _state.update {
            it.copy(isAdminLeaveConfirmationVisible = false)
        }
        performLeaveChat(confirmDelete = true)
    }

    private fun dismissAdminLeaveConfirmation() {
        _state.update {
            it.copy(isAdminLeaveConfirmationVisible = false)
        }
    }

    private fun performLeaveChat(confirmDelete: Boolean) {
        val chatId = _chatId.value ?: return

        viewModelScope.launch {
            chatRepository
                .leaveChat(chatId, confirmDelete)
                .onSuccess {
                    _state.value.messageTextFieldState.clearText()

                    _chatId.update { null }
                    _state.update {
                        it.copy(
                            chatUi = null,
                            messages = emptyList(),
                            bannerState = BannerState()
                        )
                    }

                    eventChannel.send(
                        ChatDetailEvent.OnChatLeft
                    )
                }
                .onFailure { error ->
                    eventChannel.send(
                        ChatDetailEvent.OnError(
                            error.toUiText()
                        )
                    )
                }
        }
    }

    private fun showRemoveMemberConfirmation(userId: String) {
        _state.update {
            it.copy(memberToRemove = userId)
        }
    }

    private fun dismissRemoveMemberConfirmation() {
        _state.update {
            it.copy(memberToRemove = null)
        }
    }

    private fun confirmRemoveMember() {
        val chatId = _chatId.value ?: return
        val userId = _state.value.memberToRemove ?: return

        _state.update {
            it.copy(memberToRemove = null)
        }

        viewModelScope.launch {
            chatRepository
                .removeParticipant(chatId, userId)
                .onFailure { error ->
                    eventChannel.send(
                        ChatDetailEvent.OnError(error.toUiText())
                    )
                }
        }
    }

    private fun onDismissChatOptions() {
        _state.update {
            it.copy(
                isChatOptionsOpen = false
            )
        }
    }

    private fun onChatOptionsClick() {
        _state.update {
            it.copy(
                isChatOptionsOpen = true
            )
        }
    }

    private fun switchChat(chatId: String?) {
        viewModelScope.launch {
            val previousChatId = _chatId.value
            if (previousChatId != null) {
                connectionClient.sendTypingEvent(previousChatId, false)
            }

            _chatId.update { chatId }

            chatId?.let {
                chatRepository.fetchChatById(chatId)
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        _chatId.value?.let { chatId ->
            viewModelScope.launch {
                connectionClient.sendTypingEvent(chatId, false)
            }
        }
    }
}
