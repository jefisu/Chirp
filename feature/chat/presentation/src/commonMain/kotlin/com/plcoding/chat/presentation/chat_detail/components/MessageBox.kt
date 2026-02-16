package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.cloud_off_icon
import chirp.feature.chat.presentation.generated.resources.send
import chirp.feature.chat.presentation.generated.resources.send_a_message
import com.plcoding.chat.domain.models.ConnectionState
import com.plcoding.chat.presentation.model.VoiceRecordingState
import com.plcoding.chat.presentation.util.toUiText
import com.plcoding.core.designsystem.components.buttons.ChirpButton
import com.plcoding.core.designsystem.components.icon.AttachFileOutlinedIcon
import com.plcoding.core.designsystem.components.textfields.ChirpMultiLineTextField
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun MessageBox(
    messageTextFieldState: TextFieldState,
    isSendButtonEnabled: Boolean,
    connectionState: ConnectionState,
    attachedImages: List<PickedImageData>,
    voiceRecordingState: VoiceRecordingState,
    onSendClick: () -> Unit,
    onAttachFilesClick: () -> Unit,
    onMicrophoneClick: () -> Unit,
    onCancelRecording: () -> Unit,
    onPauseRecording: () -> Unit,
    onDiscardRecording: () -> Unit,
    onResumeRecording: () -> Unit,
    onSendVoiceMessage: () -> Unit,
    onPreviewVoiceMessage: () -> Unit,
    onRemoveAttachmentClick: (PickedImageData) -> Unit,
    onImageClick: (PickedImageData) -> Unit,
    modifier: Modifier = Modifier,
    isRecordingPlaying: Boolean = false,
    recordingPlaybackProgress: Float = 0f,
) {
    val isConnected = connectionState == ConnectionState.CONNECTED
    val deviceConfiguration = currentDeviceConfiguration()
    val hasText = messageTextFieldState.text.toString().isNotBlank()
    val hasAttachments = attachedImages.isNotEmpty()
    val isRecording = voiceRecordingState is VoiceRecordingState.Recording
    val isPaused = voiceRecordingState is VoiceRecordingState.Paused

    val networkConnection = @Composable {
        if (!isConnected) {
            Icon(
                imageVector = vectorResource(Res.drawable.cloud_off_icon),
                contentDescription = connectionState.toUiText().asString(),
                modifier = Modifier.size(16.dp),
                tint = MaterialTheme.colorScheme.extended.textDisabled,
            )
            Spacer(Modifier.width(4.dp))
            Text(
                text = connectionState.toUiText().asString(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.extended.textDisabled,
            )
        }
    }

    @Composable
    fun sendOptions(modifier: Modifier = Modifier) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            modifier = modifier
        ) {
            Spacer(modifier = Modifier.weight(1f))
            networkConnection()
            AttachFileOutlinedIcon(
                enabled = isConnected && !hasText,
                onClick = onAttachFilesClick
            )
            if (hasText || hasAttachments) {
                ChirpButton(
                    text = stringResource(Res.string.send),
                    onClick = onSendClick,
                    enabled = isConnected && isSendButtonEnabled,
                )
            } else {
                FilledIconButton(
                    onClick = onMicrophoneClick,
                    enabled = isConnected && !isRecording,
                    shape = MaterialTheme.shapes.small,
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                        disabledContentColor = MaterialTheme.colorScheme.extended.textDisabled,
                        disabledContainerColor = MaterialTheme.colorScheme.extended.disabledFill
                    ),
                    modifier = Modifier
                        .size(44.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Mic,
                        contentDescription = "Record voice",
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }

    @Composable
    fun attachments(modifier: Modifier = Modifier) {
        AttachmentsList(
            pickedImages = attachedImages,
            onRemoveClick = onRemoveAttachmentClick,
            onImageClick = onImageClick,
            modifier = modifier,
        )
    }

    val bottomContent: @Composable RowScope.() -> Unit = {
        when (deviceConfiguration) {
            DeviceConfiguration.DESKTOP,
            DeviceConfiguration.TABLET_PORTRAIT,
            DeviceConfiguration.TABLET_LANDSCAPE,
            DeviceConfiguration.MOBILE_LANDSCAPE -> {
                AnimatedVisibility(
                    visible = attachedImages.isNotEmpty(),
                    enter = slideInHorizontally() + fadeIn(),
                    exit = slideOutHorizontally() + fadeOut()
                ) {
                    attachments()
                }
                sendOptions(
                    modifier = Modifier
                        .align(Alignment.Bottom)
                )
            }

            DeviceConfiguration.MOBILE_PORTRAIT -> Column {
                AnimatedVisibility(visible = attachedImages.isNotEmpty()) {
                    attachments(
                        modifier = Modifier
                            .padding(bottom = 12.dp, top = 8.dp)
                    )
                }
                sendOptions()
            }
        }
    }

    if (isRecording || isPaused) {
        VoiceRecordingControls(
            state = voiceRecordingState,
            isConnected = isConnected,
            isPlaying = isRecordingPlaying,
            playbackProgress = recordingPlaybackProgress,
            onDiscardRecording = onDiscardRecording,
            onResumeRecording = onResumeRecording,
            onSendVoiceMessage = onSendVoiceMessage,
            onPreviewVoiceMessage = onPreviewVoiceMessage,
            onCancelRecording = onCancelRecording,
            onPauseRecording = onPauseRecording,
            modifier = modifier
                .padding(vertical = 8.dp)
        )
    } else {
        ChirpMultiLineTextField(
            state = messageTextFieldState,
            modifier = modifier
                .onPreviewKeyEvent { keyEvent ->
                    val isModifierKeyPressed = keyEvent.isMetaPressed || keyEvent.isCtrlPressed
                    val isSendShortcutPressed = isModifierKeyPressed
                            && keyEvent.key == Key.Enter
                            && keyEvent.type == KeyEventType.KeyDown

                    if (isSendShortcutPressed) {
                        onSendClick()
                        true
                    } else false
                },
            placeholder = stringResource(Res.string.send_a_message),
            keyboardOptions = KeyboardOptions(
                imeAction = ImeAction.Send
            ),
            onKeyboardAction = onSendClick,
            bottomContent = bottomContent
        )
    }
}

@Composable
@Preview
fun MessageBoxPreview() {
    ChirpTheme {
        MessageBox(
            messageTextFieldState = rememberTextFieldState(),
            isSendButtonEnabled = true,
            connectionState = ConnectionState.CONNECTED,
            attachedImages = emptyList(),
            voiceRecordingState = VoiceRecordingState.Idle,
            onSendClick = {},
            onAttachFilesClick = {},
            onMicrophoneClick = {},
            onCancelRecording = {},
            onPauseRecording = {},
            onDiscardRecording = {},
            onResumeRecording = {},
            onSendVoiceMessage = {},
            onPreviewVoiceMessage = {},
            onRemoveAttachmentClick = {},
            onImageClick = {},
            modifier = Modifier
                .fillMaxWidth()
        )
    }
}
