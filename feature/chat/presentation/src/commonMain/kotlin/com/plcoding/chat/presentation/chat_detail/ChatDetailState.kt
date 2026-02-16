package com.plcoding.chat.presentation.chat_detail

import androidx.compose.foundation.text.input.TextFieldState
import com.plcoding.chat.domain.models.ConnectionState
import com.plcoding.chat.presentation.model.AudioPlaybackState
import com.plcoding.chat.presentation.model.ChatUi
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.model.VoiceRecordingState
import com.plcoding.chat.presentation.util.TypingUsers
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.UiText

data class ChatDetailState(
    val chatUi: ChatUi? = null,
    val isLoading: Boolean = false,
    val messages: List<MessageUi> = emptyList(),
    val error: UiText? = null,
    val messageTextFieldState: TextFieldState = TextFieldState(),
    val canSendMessage: Boolean = false,
    val isPaginationLoading: Boolean = false,
    val paginationError: UiText? = null,
    val endReached: Boolean = false,
    val messageWithOpenMenu: MessageUi.LocalUser? = null,
    val attachmentWithOpenMenu: MessageAttachmentUi? = null,
    val bannerState: BannerState = BannerState(),
    val isChatOptionsOpen: Boolean = false,
    val isNearBottom: Boolean = false,
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val imagesSelected: List<PickedImageData> = emptyList(),
    val attachmentPreviewData: Any? = null,
    val typingUsers: TypingUsers = emptyMap(),
    val isAdminLeaveConfirmationVisible: Boolean = false,
    val memberToRemove: String? = null,
    val voiceRecordingState: VoiceRecordingState = VoiceRecordingState.Idle,
    val audioPlaybackState: AudioPlaybackState = AudioPlaybackState()
)

data class BannerState(
    val formattedDate: UiText? = null,
    val isVisible: Boolean = false
)
