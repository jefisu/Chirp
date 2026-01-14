package com.plcoding.chat.presentation.chat_list_detail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.plcoding.chat.domain.chat.ChatConnectionClient
import com.plcoding.chat.domain.models.TypingEvent
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlin.time.Duration.Companion.seconds

class ChatListDetailViewModel(
    private val connectionClient: ChatConnectionClient
) : ViewModel() {

    private var hasLoadedInitialData = false
    private val typingJobs = mutableMapOf<String, Job>()

    private val _state = MutableStateFlow(ChatListDetailState())
    val state = _state
        .onStart {
            if (!hasLoadedInitialData) {
                connectionClient.chatMessages.launchIn(viewModelScope)
                observeTypingEvents()
                hasLoadedInitialData = true
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = ChatListDetailState()
        )

    fun onAction(action: ChatListDetailAction) {
        when(action) {
            is ChatListDetailAction.OnSelectChat -> {
                _state.update { it.copy(
                    selectedChatId = action.chatId
                ) }
            }
            ChatListDetailAction.OnCreateChatClick -> {
                _state.update { it.copy(
                    dialogState = DialogState.CreateChat
                ) }
            }
            ChatListDetailAction.OnDismissCurrentDialog -> {
                _state.update { it.copy(
                    dialogState = DialogState.Hidden
                ) }
            }
            ChatListDetailAction.OnManageChatClick -> {
                state.value.selectedChatId?.let { id ->
                    _state.update { it.copy(
                        dialogState = DialogState.ManageChat(id)
                    ) }
                }
            }
            ChatListDetailAction.OnProfileSettingsClick -> {
                _state.update { it.copy(
                    dialogState = DialogState.Profile
                ) }
            }
        }
    }

    private fun observeTypingEvents() {
        connectionClient
            .typingEvents
            .onEach { event ->
                handleTypingEvent(event)
            }
            .launchIn(viewModelScope)
    }

    private fun handleTypingEvent(event: TypingEvent) {
        if (event.isTyping) {
            _state.update { currentState ->
                val currentChatTyping = currentState.typingUsersByChat[event.chatId] ?: emptyMap()
                val updatedChatTyping = currentChatTyping + (event.userId to event.userName)
                currentState.copy(
                    typingUsersByChat = currentState.typingUsersByChat + (event.chatId to updatedChatTyping)
                )
            }

            typingJobs[event.userId]?.cancel()
            typingJobs[event.userId] = viewModelScope.launch {
                delay(3.seconds)
                removeTypingUser(event.chatId, event.userId)
            }
        } else {
            typingJobs[event.userId]?.cancel()
            removeTypingUser(event.chatId, event.userId)
        }
    }

    private fun removeTypingUser(chatId: String, userId: String) {
        _state.update { currentState ->
            val currentChatTyping =
                currentState.typingUsersByChat[chatId] ?: return@update currentState
            val updatedChatTyping = currentChatTyping - userId

            val updatedTypingMap = if (updatedChatTyping.isEmpty()) {
                currentState.typingUsersByChat - chatId
            } else {
                currentState.typingUsersByChat + (chatId to updatedChatTyping)
            }

            currentState.copy(typingUsersByChat = updatedTypingMap)
        }
    }
}
