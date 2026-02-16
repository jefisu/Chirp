package com.plcoding.chat.presentation.chat_list

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.plcoding.chat.domain.audio.AudioMetadataRepository
import com.plcoding.chat.domain.chat.ChatRepository
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.notification.DeviceTokenService
import com.plcoding.chat.domain.participant.ChatParticipantRepository
import com.plcoding.chat.presentation.chat_list_detail.ChatListDetailState
import com.plcoding.chat.presentation.mappers.toUi
import com.plcoding.core.domain.auth.AuthService
import com.plcoding.core.domain.auth.SessionStorage
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import com.plcoding.core.presentation.util.toUiText
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class ChatListViewModel(
    private val repository: ChatRepository,
    private val sessionStorage: SessionStorage,
    private val deviceTokenService: DeviceTokenService,
    private val authService: AuthService,
    private val chatParticipantRepository: ChatParticipantRepository,
    private val sharedState: StateFlow<ChatListDetailState>,
    private val audioMetadataRepository: AudioMetadataRepository,
) : ViewModel() {
    private val eventChannel = Channel<ChatListEvent>()
    val events = eventChannel.receiveAsFlow()

    private var hasLoadedInitialData = false

    private val _state = MutableStateFlow(ChatListState())
    val state = combine(
        _state,
        repository.getChats(),
        sessionStorage.observeAuthInfo(),
        sharedState,
        audioMetadataRepository.getAllAudioMetadata(),
    ) { currentState, chats, authInfo, sharedState, metadataList ->
        if (authInfo == null) {
            return@combine ChatListState()
        }

        val metadataMap = metadataList.associateBy { it.attachmentId }

        currentState.copy(
            chats = chats.map { chat ->
                val voiceMessage = chat.lastMessage?.attachments?.firstOrNull {
                    it.type == MessageAttachmentType.AUDIO
                }
                val durationMs = voiceMessage?.let { metadataMap[it.id]?.durationMs }
                chat.toUi(
                    localParticipantId = authInfo.user.id,
                    audioDurationMs = durationMs
                )
            },
            localParticipant = authInfo.user.toUi(),
            typingUsersByChat = sharedState.typingUsersByChat
        )
    }
        .onStart {
            if (!hasLoadedInitialData) {
                loadChats()
                fetchLocalUserProfile()
                hasLoadedInitialData = true
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = ChatListState()
        )

    fun onAction(action: ChatListAction) {
        when (action) {
            is ChatListAction.OnSelectChat -> {
                _state.update { it.copy(
                    selectedChatId = action.chatId
                ) }
            }
            ChatListAction.OnUserAvatarClick -> {
                _state.update { it.copy(
                    isUserMenuOpen = true
                ) }
            }
            ChatListAction.OnLogoutClick -> showLogoutConfirmation()
            ChatListAction.OnConfirmLogout -> logout()
            ChatListAction.OnDismissLogoutDialog -> {
                _state.update { it.copy(
                    showLogoutConfirmation = false
                ) }
            }
            ChatListAction.OnProfileSettingsClick,
            ChatListAction.OnDismissUserMenu -> {
                _state.update { it.copy(
                    isUserMenuOpen = false
                ) }
            }
            else -> Unit
        }
    }

    private fun fetchLocalUserProfile() {
        viewModelScope.launch {
            chatParticipantRepository.fetchLocalParticipant()
        }
    }

    private fun logout() {
        _state.update { it.copy(
            showLogoutConfirmation = false
        ) }

        viewModelScope.launch {
            val authInfo = sessionStorage.observeAuthInfo().first()
            val refreshToken = authInfo?.refreshToken ?: return@launch

            deviceTokenService
                .unregisterToken(refreshToken)
                .onSuccess {
                    authService
                        .logout(refreshToken)
                        .onSuccess {
                            sessionStorage.set(null)
                            repository.deleteAllChats()
                            eventChannel.send(ChatListEvent.OnLogoutSuccess)
                        }.onFailure { error ->
                            eventChannel.send(ChatListEvent.OnLogoutError(error.toUiText()))
                        }
                }.onFailure { error ->
                    eventChannel.send(ChatListEvent.OnLogoutError(error.toUiText()))
                }
        }
    }

    private fun showLogoutConfirmation() {
        _state.update { it.copy(
            isUserMenuOpen = false,
            showLogoutConfirmation = true
        ) }
    }

    private fun loadChats() {
        viewModelScope.launch {
            repository.fetchChats()
        }
    }
}
