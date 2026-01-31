package com.plcoding.chat.presentation.components.manage_chat

sealed interface ManageChatAction {
    data object OnAddClick: ManageChatAction
    data object OnDismissDialog: ManageChatAction
    data object OnPrimaryActionClick: ManageChatAction
    data class OnRemoveMemberClick(val userId: String): ManageChatAction
    data object OnConfirmRemoveMember: ManageChatAction
    data object OnDismissRemoveMemberConfirmation: ManageChatAction

    sealed interface ChatParticipants: ManageChatAction {
        data class OnSelectChat(val chatId: String?): ManageChatAction
    }
}