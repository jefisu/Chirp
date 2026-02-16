package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.plcoding.chat.presentation.model.AudioPlaybackState
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.components.avatar.ChirpAvatarPhoto
import com.plcoding.core.designsystem.components.chat.ChirpChatBubble
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.chat.TrianglePosition
import com.plcoding.core.domain.audio.PlaybackState

@Composable
fun OtherUserMessage(
    message: MessageUi.OtherUser,
    color: Color,
    audioPlaybackState: AudioPlaybackState,
    onAttachmentLongClick: (MessageAttachmentUi) -> Unit,
    onAttachmentClick: (MessageAttachmentUi) -> Unit,
    onPlayAudioClick: (MessageAttachmentUi.Audio) -> Unit,
    onPauseAudioClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth(),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ChirpAvatarPhoto(
            displayText = message.sender.initials,
            imageUrl = message.sender.imageUrl,
        )
        when (message) {
            is MessageUi.OtherUser.Message -> {
                ChirpChatBubble(
                    messageContent = message.content,
                    sender = message.sender.username,
                    trianglePosition = TrianglePosition.LEFT,
                    color = color,
                    formattedDateTime = message.formattedSentTime.asString(),
                    attachments = message.attachments,
                    onAttachmentClick = onAttachmentClick,
                    onAttachmentLongClick = onAttachmentLongClick,
                )
            }

            is MessageUi.OtherUser.Audio -> {
                val audioAttachment = message.attachment
                val isPlaying = audioPlaybackState.playingAttachmentId == audioAttachment.id
                        && audioPlaybackState.playbackState == PlaybackState.PLAYING
                val isCurrentAudio = audioPlaybackState.playingAttachmentId == audioAttachment.id
                val waveformData = if (isCurrentAudio && audioPlaybackState.waveformData.isNotEmpty()) {
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
                    sender = message.sender.username,
                    formattedDateTime = message.formattedSentTime.asString(),
                    trianglePosition = TrianglePosition.LEFT,
                    color = color,
                    onPlayPauseClick = {
                        if (isPlaying) {
                            onPauseAudioClick()
                        } else {
                            onPlayAudioClick(audioAttachment)
                        }
                    },
                )
            }
        }
    }
}
