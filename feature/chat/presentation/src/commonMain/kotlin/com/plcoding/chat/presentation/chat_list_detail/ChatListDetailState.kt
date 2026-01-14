package com.plcoding.chat.presentation.chat_list_detail

import com.plcoding.chat.presentation.util.TypingUsersByChat

data class ChatListDetailState(
    val selectedChatId: String? = null,
    val dialogState: DialogState = DialogState.Hidden,
    val typingUsersByChat: TypingUsersByChat = emptyMap()
)

sealed interface DialogState {
    data object Hidden: DialogState
    data object CreateChat: DialogState
    data object Profile: DialogState
    data class ManageChat(val chatId: String): DialogState
}
