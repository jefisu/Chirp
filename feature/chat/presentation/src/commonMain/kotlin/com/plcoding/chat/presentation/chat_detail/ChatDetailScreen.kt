@file:OptIn(ExperimentalUuidApi::class, ExperimentalComposeUiApi::class)

package com.plcoding.chat.presentation.chat_detail

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.draganddrop.dragAndDropTarget
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.backhandler.BackHandler
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.admin_leave_confirmation_desc
import chirp.feature.chat.presentation.generated.resources.admin_leave_confirmation_title
import chirp.feature.chat.presentation.generated.resources.cancel
import chirp.feature.chat.presentation.generated.resources.drop_images_to_share
import chirp.feature.chat.presentation.generated.resources.leave_chat
import chirp.feature.chat.presentation.generated.resources.microphone_permission_required
import chirp.feature.chat.presentation.generated.resources.no_chat_selected
import chirp.feature.chat.presentation.generated.resources.remove
import chirp.feature.chat.presentation.generated.resources.remove_member
import chirp.feature.chat.presentation.generated.resources.remove_member_confirmation
import chirp.feature.chat.presentation.generated.resources.select_a_chat
import coil3.compose.rememberAsyncImagePainter
import com.plcoding.chat.presentation.chat_detail.components.AttachmentContextMenu
import com.plcoding.chat.presentation.chat_detail.components.ChatDetailHeader
import com.plcoding.chat.presentation.chat_detail.components.DateChip
import com.plcoding.chat.presentation.chat_detail.components.ImagePreviewDialog
import com.plcoding.chat.presentation.chat_detail.components.MessageBannerListener
import com.plcoding.chat.presentation.chat_detail.components.MessageBox
import com.plcoding.chat.presentation.chat_detail.components.MessageList
import com.plcoding.chat.presentation.chat_detail.components.PaginationScrollListener
import com.plcoding.chat.presentation.chat_detail.components.TypingFormatter
import com.plcoding.chat.presentation.chat_detail.components.TypingIndicator
import com.plcoding.chat.presentation.components.ChatHeader
import com.plcoding.chat.presentation.components.EmptySection
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.profile.components.DragAndDropOverlay
import com.plcoding.chat.presentation.util.ChatPreviewData
import com.plcoding.core.designsystem.components.dialogs.DestructiveConfirmationDialog
import com.plcoding.core.designsystem.components.dialogs.ErrorDialog
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.domain.audio.PlaybackState
import com.plcoding.core.presentation.media.ImagePickerMode
import com.plcoding.core.presentation.media.rememberDragAndDropTarget
import com.plcoding.core.presentation.media.rememberImagePickerLauncher
import com.plcoding.core.presentation.permissions.Permission
import com.plcoding.core.presentation.permissions.PermissionState
import com.plcoding.core.presentation.permissions.rememberPermissionController
import com.plcoding.core.presentation.util.ObserveAsEvents
import com.plcoding.core.presentation.util.UiText
import com.plcoding.core.presentation.util.clearFocusOnTap
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.koin.compose.viewmodel.koinViewModel
import kotlin.uuid.ExperimentalUuidApi

@Composable
fun ChatDetailRoot(
    chatId: String?,
    isDetailPresent: Boolean,
    onBack: () -> Unit,
    onChatMembersClick: () -> Unit,
    viewModel: ChatDetailViewModel = koinViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    val snackbarState = remember { SnackbarHostState() }
    val messageListState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val permissionController = rememberPermissionController()

    ObserveAsEvents(viewModel.events) { event ->
        when (event) {
            ChatDetailEvent.OnChatLeft -> onBack()
            ChatDetailEvent.OnNewMessage -> {
                scope.launch {
                    messageListState.animateScrollToItem(0)
                }
            }

            is ChatDetailEvent.OnError -> {
                snackbarState.showSnackbar(event.error.asStringAsync())
            }
        }
    }

    LaunchedEffect(chatId) {
        viewModel.onAction(ChatDetailAction.OnSelectChat(chatId))
    }

    LaunchedEffect(chatId, state.messages) {
        if (state.messages.isNotEmpty()) {
            messageListState.scrollToItem(0)
        }
    }

    BackHandler(
        enabled = !isDetailPresent,
    ) {
        scope.launch {
            // Add artificial delay to prevent detail back animation from showing
            // an unselected chat the moment we go back
            delay(300)
            viewModel.onAction(ChatDetailAction.OnSelectChat(null))
        }
        onBack()
    }

    ChatDetailScreen(
        state = state,
        messageListState = messageListState,
        isDetailPresent = isDetailPresent,
        onAction = { action ->
            when (action) {
                is ChatDetailAction.OnChatMembersClick -> onChatMembersClick()
                is ChatDetailAction.OnBackClick -> onBack()
                is ChatDetailAction.OnMicrophoneClick ->
                    scope.launch {
                        val permission =
                            permissionController.requestPermission(Permission.RECORD_AUDIO)
                        if (permission != PermissionState.GRANTED) {
                            snackbarState.showSnackbar(
                                UiText
                                    .Resource(Res.string.microphone_permission_required)
                                    .asStringAsync(),
                            )
                        }
                    }

                else -> Unit
            }
            viewModel.onAction(action)
        },
        snackbarState = snackbarState,
        onEvent = viewModel::onEvent,
    )
}

@Composable
fun ChatDetailScreen(
    state: ChatDetailState,
    messageListState: LazyListState,
    isDetailPresent: Boolean,
    snackbarState: SnackbarHostState,
    onAction: (ChatDetailAction) -> Unit,
    onEvent: (ChatDetailEvent) -> Unit,
) {
    val configuration = currentDeviceConfiguration()

    val realMessageItemCount = remember(state.messages) {
        state
            .messages
            .filter { it is MessageUi.LocalUser || it is MessageUi.OtherUser }
            .size
    }

    val imagePickerLauncher = rememberImagePickerLauncher(
        mode = ImagePickerMode.Multiple(maxItems = 10),
        onError = { error ->
            onEvent(ChatDetailEvent.OnError(error))
        }
    ) { pickedImages ->
        onAction(ChatDetailAction.OnImagesSelected(pickedImages))
    }

    var isHoveringWithFiles by rememberSaveable { mutableStateOf(false) }
    val dragAndDropTarget = rememberDragAndDropTarget(
        mode = ImagePickerMode.Multiple(maxItems = 10),
        onHover = { isHovered ->
            isHoveringWithFiles = isHovered
        },
        onDrop = { droppedImages ->
            onAction(ChatDetailAction.OnImagesSelected(droppedImages))
        },
        onError = { error ->
            onEvent(ChatDetailEvent.OnError(error))
        }
    )
    if (isHoveringWithFiles && state.chatUi != null) {
        DragAndDropOverlay(
            modifier = Modifier.zIndex(1f),
            description = stringResource(Res.string.drop_images_to_share)
        )
    }

    ImagePreviewDialog(
        isVisible = state.attachmentPreviewData != null,
        painter = rememberAsyncImagePainter(state.attachmentPreviewData),
        onDismiss = {
            onAction(ChatDetailAction.OnDismissImagePreview)
        }
    )

    LaunchedEffect(messageListState) {
        snapshotFlow {
            messageListState.firstVisibleItemIndex to messageListState.layoutInfo.totalItemsCount
        }.filter { (firstVisibleIndex, totalItemsCount) ->
            firstVisibleIndex >= 0 && totalItemsCount > 0
        }.collect { (firstVisibleItemIndex, _) ->
            onAction(ChatDetailAction.OnFirstVisibleIndexChanged(firstVisibleItemIndex))
        }
    }

    MessageBannerListener(
        lazyListState = messageListState,
        messages = state.messages,
        isBannerVisible = state.bannerState.isVisible,
        onShowBanner = { index ->
            onAction(ChatDetailAction.OnTopVisibleIndexChanged(index))
        },
        onHide = {
            onAction(ChatDetailAction.OnHideBanner)
        }
    )

    PaginationScrollListener(
        lazyListState = messageListState,
        itemCount = realMessageItemCount,
        isPaginationLoading = state.isPaginationLoading,
        isEndReached = state.endReached,
        onNearTop = {
            onAction(ChatDetailAction.OnScrollToTop)
        }
    )

    AttachmentContextMenu(
        attachment = state.attachmentWithOpenMenu,
        onDismiss = { onAction(ChatDetailAction.OnDismissAttachmentMenu) },
        onSaveClick = {
            state.attachmentWithOpenMenu?.let {
                onAction(ChatDetailAction.OnSaveAttachmentClick(it))
            }
        }
    )

    var headerHeight by remember {
        mutableStateOf(0.dp)
    }
    val density = LocalDensity.current

    val isRecordingPlaying =
        state.audioPlaybackState.playingAttachmentId == null
                && (state.audioPlaybackState.playbackState == PlaybackState.PLAYING
                || state.audioPlaybackState.playbackState == PlaybackState.PAUSED)

    val recordingPlaybackProgress =
        if (isRecordingPlaying && state.audioPlaybackState.duration > 0) {
            state.audioPlaybackState.currentPosition.toFloat() / state.audioPlaybackState.duration
        } else 0f

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .dragAndDropTarget(
                shouldStartDragAndDrop = { state.chatUi != null },
                target = dragAndDropTarget
            )
            .blur(
                radius = when {
                    state.attachmentPreviewData != null || state.attachmentWithOpenMenu != null -> 20.dp
                    else -> 0.dp
                }
            ),
        containerColor = if (!configuration.isWideScreen) {
            MaterialTheme.colorScheme.surface
        } else {
            MaterialTheme.colorScheme.extended.surfaceLower
        },
        snackbarHost = {
            SnackbarHost(snackbarState)
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .clearFocusOnTap()
                .padding(innerPadding)
                .then(
                    if (configuration.isWideScreen) Modifier.padding(horizontal = 8.dp)
                    else Modifier
                )
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                DynamicRoundedCornerColumn(
                    isCornersRounded = configuration.isWideScreen,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                ) {
                    if (state.chatUi == null) {
                        EmptySection(
                            title = stringResource(Res.string.no_chat_selected),
                            description = stringResource(Res.string.select_a_chat),
                            modifier = Modifier
                                .fillMaxSize()
                        )
                    } else {
                        ChatHeader(
                            modifier = Modifier
                                .onSizeChanged {
                                    headerHeight = with(density) {
                                        it.height.toDp()
                                    }
                                }
                        ) {
                            ChatDetailHeader(
                                chatUi = state.chatUi,
                                isDetailPresent = isDetailPresent,
                                isChatOptionsDropDownOpen = state.isChatOptionsOpen,
                                onChatOptionsClick = {
                                    onAction(ChatDetailAction.OnChatOptionsClick)
                                },
                                onDismissChatOptions = {
                                    onAction(ChatDetailAction.OnDismissChatOptions)
                                },
                                onManageChatClick = {
                                    onAction(ChatDetailAction.OnChatMembersClick)
                                },
                                onLeaveChatClick = {
                                    onAction(ChatDetailAction.OnLeaveChatClick)
                                },
                                onBackClick = {
                                    onAction(ChatDetailAction.OnBackClick)
                                },
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        MessageList(
                            messages = state.messages,
                            messageWithOpenMenu = state.messageWithOpenMenu,
                            audioPlaybackState = state.audioPlaybackState,
                            listState = messageListState,
                            isPaginationLoading = state.isPaginationLoading,
                            paginationError = state.paginationError?.asString(),
                            onMessageLongClick = { message ->
                                onAction(ChatDetailAction.OnMessageLongClick(message))
                            },
                            onMessageRetryClick = { message ->
                                onAction(ChatDetailAction.OnRetryClick(message))
                            },
                            onDismissMessageMenu = {
                                onAction(ChatDetailAction.OnDismissMessageMenu)
                            },
                            onDeleteMessageClick = { message ->
                                onAction(ChatDetailAction.OnDeleteMessageClick(message))
                            },
                            onRetryPaginationClick = {
                                onAction(ChatDetailAction.OnRetryPaginationClick)
                            },
                            onAttachmentClick = { attachment ->
                                onAction(ChatDetailAction.OnAttachmentClick(attachment.url))
                            },
                            onAttachmentLongClick = { attachment ->
                                onAction(ChatDetailAction.OnAttachmentLongClick(attachment))
                            },
                            onPlayAudioClick = { attachment ->
                                onAction(
                                    ChatDetailAction.OnPlayAudioClick(
                                        attachment.id,
                                        attachment.url
                                    )
                                )
                            },
                            onPauseAudioClick = {
                                val playingId = state.audioPlaybackState.playingAttachmentId
                                if (playingId != null) {
                                    onAction(ChatDetailAction.OnPauseAudioClick(playingId))
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f)
                        )

                        TypingIndicator(
                            typingText = TypingFormatter
                                .format(state.typingUsers.values.toList())
                                ?.asString(),
                            modifier = Modifier
                                .padding(
                                    vertical = if (configuration.isMobile) 8.dp else 20.dp,
                                    horizontal = if (configuration.isMobile) 16.dp else 24.dp
                                )
                        )

                        AnimatedVisibility(
                            visible = !configuration.isWideScreen,
                        ) {
                            MessageBox(
                                messageTextFieldState = state.messageTextFieldState,
                                isSendButtonEnabled = state.canSendMessage,
                                connectionState = state.connectionState,
                                attachedImages = state.imagesSelected,
                                voiceRecordingState = state.voiceRecordingState,
                                isRecordingPlaying = isRecordingPlaying && state.audioPlaybackState.playbackState == PlaybackState.PLAYING,
                                recordingPlaybackProgress = recordingPlaybackProgress,
                                onSendClick = {
                                    onAction(ChatDetailAction.OnSendMessageClick)
                                },
                                onAttachFilesClick = imagePickerLauncher::launch,
                                onMicrophoneClick = {
                                    onAction(ChatDetailAction.OnMicrophoneClick)
                                },
                                onCancelRecording = {
                                    onAction(ChatDetailAction.OnCancelRecording)
                                },
                                onPauseRecording = {
                                    onAction(ChatDetailAction.OnPauseRecording)
                                },
                                onDiscardRecording = {
                                    onAction(ChatDetailAction.OnDiscardRecording)
                                },
                                onSendVoiceMessage = {
                                    onAction(ChatDetailAction.OnSendVoiceMessage)
                                },
                                onPreviewVoiceMessage = {
                                    onAction(ChatDetailAction.OnPreviewVoiceMessage)
                                },
                                onResumeRecording = {
                                    onAction(ChatDetailAction.OnResumeRecording)
                                },
                                onRemoveAttachmentClick = {
                                    onAction(ChatDetailAction.OnRemoveImageSelected(it))
                                },
                                onImageClick = {
                                    onAction(ChatDetailAction.OnAttachmentClick(it.bytes))
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .imePadding()
                                    .padding(
                                        vertical = 8.dp,
                                        horizontal = 16.dp
                                    )
                            )
                        }
                    }
                }

                if (configuration.isWideScreen) {
                    Spacer(modifier = Modifier.height(8.dp))
                }

                AnimatedVisibility(
                    visible = configuration.isWideScreen && state.chatUi != null
                ) {
                    DynamicRoundedCornerColumn(
                        isCornersRounded = configuration.isWideScreen,
                    ) {
                        MessageBox(
                            messageTextFieldState = state.messageTextFieldState,
                            isSendButtonEnabled = state.canSendMessage,
                            connectionState = state.connectionState,
                            attachedImages = state.imagesSelected,
                            voiceRecordingState = state.voiceRecordingState,
                            isRecordingPlaying = isRecordingPlaying && state.audioPlaybackState.playbackState == PlaybackState.PLAYING,
                            recordingPlaybackProgress = recordingPlaybackProgress,
                            onSendClick = {
                                onAction(ChatDetailAction.OnSendMessageClick)
                            },
                            onAttachFilesClick = imagePickerLauncher::launch,
                            onMicrophoneClick = {
                                onAction(ChatDetailAction.OnMicrophoneClick)
                            },
                            onCancelRecording = {
                                onAction(ChatDetailAction.OnCancelRecording)
                            },
                            onPauseRecording = {
                                onAction(ChatDetailAction.OnPauseRecording)
                            },
                            onDiscardRecording = {
                                onAction(ChatDetailAction.OnDiscardRecording)
                            },
                            onSendVoiceMessage = {
                                onAction(ChatDetailAction.OnSendVoiceMessage)
                            },
                            onPreviewVoiceMessage = {
                                onAction(ChatDetailAction.OnPreviewVoiceMessage)
                            },
                            onResumeRecording = {
                                onAction(ChatDetailAction.OnResumeRecording)
                            },
                            onRemoveAttachmentClick = {
                                onAction(ChatDetailAction.OnRemoveImageSelected(it))
                            },
                            onImageClick = {
                                onAction(ChatDetailAction.OnAttachmentClick(it.bytes))
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .imePadding()
                                .padding(8.dp)
                        )
                    }
                }
            }

            AnimatedVisibility(
                visible = state.bannerState.isVisible,
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(top = headerHeight + 16.dp),
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                if (state.bannerState.formattedDate != null) {
                    DateChip(
                        date = state.bannerState.formattedDate.asString(),
                    )
                }
            }

            ErrorDialog(
                isVisible = state.error != null,
                description = state.error?.asString().orEmpty(),
                onDismissClick = {
                    onAction(ChatDetailAction.OnDismissErrorDialog)
                }
            )

            if (state.isAdminLeaveConfirmationVisible) {
                DestructiveConfirmationDialog(
                    title = stringResource(Res.string.admin_leave_confirmation_title),
                    description = stringResource(Res.string.admin_leave_confirmation_desc),
                    confirmButtonText = stringResource(Res.string.leave_chat),
                    cancelButtonText = stringResource(Res.string.cancel),
                    onConfirmClick = {
                        onAction(ChatDetailAction.OnConfirmAdminLeave)
                    },
                    onCancelClick = {
                        onAction(ChatDetailAction.OnDismissAdminLeaveConfirmation)
                    },
                    onDismiss = {
                        onAction(ChatDetailAction.OnDismissAdminLeaveConfirmation)
                    }
                )
            }

            val memberToRemove = state.memberToRemove
            val memberToRemoveUsername = state.chatUi
                ?.otherParticipants
                ?.find { it.id == memberToRemove }
                ?.username
            if (memberToRemove != null && memberToRemoveUsername != null) {
                DestructiveConfirmationDialog(
                    title = stringResource(Res.string.remove_member),
                    description = stringResource(
                        Res.string.remove_member_confirmation,
                        memberToRemoveUsername
                    ),
                    confirmButtonText = stringResource(Res.string.remove),
                    cancelButtonText = stringResource(Res.string.cancel),
                    onConfirmClick = {
                        onAction(ChatDetailAction.OnConfirmRemoveMember)
                    },
                    onCancelClick = {
                        onAction(ChatDetailAction.OnDismissRemoveMemberConfirmation)
                    },
                    onDismiss = {
                        onAction(ChatDetailAction.OnDismissRemoveMemberConfirmation)
                    }
                )
            }
        }
    }
}

@Composable
private fun DynamicRoundedCornerColumn(
    isCornersRounded: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier
            .shadow(
                elevation = if (isCornersRounded) 8.dp else 0.dp,
                shape = if (isCornersRounded) RoundedCornerShape(24.dp) else RectangleShape,
                spotColor = Color.Black.copy(alpha = 0.2f)
            )
            .background(
                color = MaterialTheme.colorScheme.surface,
                shape = if (isCornersRounded) RoundedCornerShape(24.dp) else RectangleShape
            )
    ) {
        content()
    }
}

@Preview
@Composable
private fun ChatDetailEmptyPreview() {
    ChirpTheme {
        ChatDetailScreen(
            state = ChatDetailState(),
            isDetailPresent = false,
            onAction = {},
            messageListState = rememberLazyListState(),
            snackbarState = remember { SnackbarHostState() },
            onEvent = {}
        )
    }
}

@Preview
@Composable
private fun ChatDetailTypingPreview() {
    ChirpTheme(darkTheme = true) {
        ChatDetailScreen(
            messageListState = rememberLazyListState(),
            state = ChatDetailState(
                chatUi = ChatPreviewData.chatUi,
                typingUsers = ChatPreviewData.typingUsers
            ),
            isDetailPresent = true,
            onAction = {},
            snackbarState = remember { SnackbarHostState() },
            onEvent = {}
        )
    }
}

@Preview
@Composable
private fun ChatDetailMessagesWithTypingPreview() {
    ChirpTheme(darkTheme = true) {
        ChatDetailScreen(
            messageListState = rememberLazyListState(),
            state = ChatPreviewData.stateWithMessagesAndTyping,
            isDetailPresent = true,
            onAction = {},
            snackbarState = remember { SnackbarHostState() },
            onEvent = {}
        )
    }
}

@Preview
@Composable
private fun ChatDetailMessagesPreview() {
    ChirpTheme(darkTheme = true) {
        ChatDetailScreen(
            messageListState = rememberLazyListState(),
            state = ChatDetailState(
                chatUi = ChatPreviewData.chatUi,
                messages = ChatPreviewData.messages,
                canSendMessage = true,
                messageTextFieldState = rememberTextFieldState(initialText = "Hello world!")
            ),
            isDetailPresent = true,
            onAction = {},
            snackbarState = remember { SnackbarHostState() },
            onEvent = {}
        )
    }
}
