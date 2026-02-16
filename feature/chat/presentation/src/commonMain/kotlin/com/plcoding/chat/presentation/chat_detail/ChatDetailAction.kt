package com.plcoding.chat.presentation.chat_detail

import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.presentation.media.PickedImageData

sealed interface ChatDetailAction {
    data object OnSendMessageClick : ChatDetailAction
    data object OnScrollToTop : ChatDetailAction
    data class OnSelectChat(val chatId: String?) : ChatDetailAction
    data class OnDeleteMessageClick(val message: MessageUi.LocalUser) : ChatDetailAction
    data class OnMessageLongClick(val message: MessageUi.LocalUser) : ChatDetailAction
    data object OnDismissMessageMenu : ChatDetailAction
    data class OnRetryClick(val message: MessageUi.LocalUser) : ChatDetailAction
    data object OnBackClick : ChatDetailAction
    data object OnChatOptionsClick : ChatDetailAction
    data object OnChatMembersClick : ChatDetailAction
    data object OnLeaveChatClick : ChatDetailAction
    data object OnDismissChatOptions : ChatDetailAction
    data object OnRetryPaginationClick : ChatDetailAction
    data object OnHideBanner : ChatDetailAction
    data class OnFirstVisibleIndexChanged(val index: Int) : ChatDetailAction
    data class OnTopVisibleIndexChanged(val topVisibleIndex: Int) : ChatDetailAction
    data class OnImagesSelected(val images: List<PickedImageData>) : ChatDetailAction
    data class OnRemoveImageSelected(val image: PickedImageData) : ChatDetailAction
    data object OnDismissImagePreview : ChatDetailAction
    data object OnDismissErrorDialog : ChatDetailAction
    data class OnAttachmentClick(val data: Any) : ChatDetailAction
    data class OnAttachmentLongClick(val attachment: MessageAttachmentUi) : ChatDetailAction
    data object OnDismissAttachmentMenu : ChatDetailAction
    data class OnSaveAttachmentClick(val attachment: MessageAttachmentUi) : ChatDetailAction
    data object OnConfirmAdminLeave : ChatDetailAction
    data object OnDismissAdminLeaveConfirmation : ChatDetailAction
    data class OnRemoveMemberClick(val userId: String) : ChatDetailAction
    data object OnConfirmRemoveMember : ChatDetailAction
    data object OnDismissRemoveMemberConfirmation : ChatDetailAction
    data object OnMicrophoneClick : ChatDetailAction
    data object OnCancelRecording : ChatDetailAction
    data object OnPauseRecording : ChatDetailAction
    data object OnResumeRecording : ChatDetailAction
    data object OnDiscardRecording : ChatDetailAction
    data object OnSendVoiceMessage : ChatDetailAction
    data object OnPreviewVoiceMessage : ChatDetailAction
    data class OnPlayAudioClick(val attachmentId: String, val url: String) : ChatDetailAction
    data class OnPauseAudioClick(val attachmentId: String, ) : ChatDetailAction
    data class OnSeekAudio(val attachmentId: String, val position: Long) : ChatDetailAction
}
