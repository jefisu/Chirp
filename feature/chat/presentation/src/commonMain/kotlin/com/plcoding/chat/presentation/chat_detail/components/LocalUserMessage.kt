package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.delete_for_everyone
import chirp.feature.chat.presentation.generated.resources.reload_icon
import chirp.feature.chat.presentation.generated.resources.retry
import chirp.feature.chat.presentation.generated.resources.you
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.presentation.model.AudioPlaybackState
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.components.chat.ChirpChatBubble
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.chat.TrianglePosition
import com.plcoding.core.designsystem.components.dropdown.ChirpDropDownMenu
import com.plcoding.core.designsystem.components.dropdown.DropDownItem
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.domain.audio.PlaybackState
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@Composable
fun LocalUserMessage(
    message: MessageUi.LocalUser,
    messageWithOpenMenu: MessageUi.LocalUser?,
    audioPlaybackState: AudioPlaybackState,
    onMessageLongClick: () -> Unit,
    onDismissMessageMenu: () -> Unit,
    onDeleteClick: () -> Unit,
    onRetryClick: () -> Unit,
    onAttachmentClick: (MessageAttachmentUi) -> Unit,
    onAttachmentLongClick: (MessageAttachmentUi) -> Unit,
    onPlayAudioClick: (MessageAttachmentUi.Audio) -> Unit,
    onPauseAudioClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth(),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
    ) {
        Box {
            when (message) {
                is MessageUi.LocalUser.Message -> {
                    ChirpChatBubble(
                        messageContent = message.content,
                        sender = stringResource(Res.string.you),
                        formattedDateTime = message.formattedSentTime.asString(),
                        trianglePosition = TrianglePosition.RIGHT,
                        attachments = message.attachments,
                        messageStatus = {
                            MessageStatus(
                                status = message.deliveryStatus,
                            )
                        },
                        onLongClick = {
                            onMessageLongClick()
                        },
                        onAttachmentClick = onAttachmentClick,
                        onAttachmentLongClick = onAttachmentLongClick
                    )
                }

                is MessageUi.LocalUser.Audio -> {
                    val audioAttachment = message.attachment
                    val isPlaying = audioPlaybackState.playingAttachmentId == audioAttachment.id
                            && audioPlaybackState.playbackState == PlaybackState.PLAYING
                    val isCurrentAudio =
                        audioPlaybackState.playingAttachmentId == audioAttachment.id
                    val waveformData =
                        if (isCurrentAudio && audioPlaybackState.waveformData.isNotEmpty()) {
                            audioPlaybackState.waveformData
                        } else {
                            audioAttachment.amplitudes
                        }
                    VoiceMessageBubble(
                        durationMs = if (isCurrentAudio && audioPlaybackState.duration > 0) {
                            audioPlaybackState.duration
                        } else {
                            audioAttachment.durationMs ?: 0L
                        },
                        isPlaying = isPlaying,
                        isLoading = isCurrentAudio && audioPlaybackState.playbackState == PlaybackState.LOADING,
                        currentPosition = if (isCurrentAudio) audioPlaybackState.currentPosition else 0L,
                        waveformData = waveformData,
                        sender = stringResource(Res.string.you),
                        formattedDateTime = message.formattedSentTime.asString(),
                        trianglePosition = TrianglePosition.RIGHT,
                        onPlayPauseClick = {
                            if (isPlaying) {
                                onPauseAudioClick()
                            } else {
                                onPlayAudioClick(audioAttachment)
                            }
                        },
                        onLongClick = onMessageLongClick,
                        messageStatus = {
                            MessageStatus(
                                status = message.deliveryStatus,
                            )
                        }
                    )
                }
            }

            ChirpDropDownMenu(
                isOpen = message.id == messageWithOpenMenu?.id,
                onDismiss = onDismissMessageMenu,
                items = listOf(
                    DropDownItem(
                        title = stringResource(Res.string.delete_for_everyone),
                        icon = Icons.Default.Delete,
                        contentColor = MaterialTheme.colorScheme.extended.destructiveHover,
                        onClick = onDeleteClick,
                    ),
                ),
            )
        }

        if (message.deliveryStatus == ChatMessageDeliveryStatus.FAILED) {
            IconButton(
                onClick = onRetryClick,
            ) {
                Icon(
                    imageVector = vectorResource(Res.drawable.reload_icon),
                    contentDescription = stringResource(Res.string.retry),
                    tint = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}
