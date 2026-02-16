package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.cancel
import chirp.feature.chat.presentation.generated.resources.send
import com.plcoding.chat.presentation.model.VoiceRecordingState
import com.plcoding.chat.presentation.util.formatDuration
import com.plcoding.core.designsystem.components.buttons.ChirpButton
import com.plcoding.core.designsystem.components.buttons.ChirpButtonStyle
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.domain.media.File
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun VoiceRecordingControls(
    state: VoiceRecordingState,
    isConnected: Boolean,
    isPlaying: Boolean = false,
    playbackProgress: Float = 0f,
    onDiscardRecording: () -> Unit,
    onResumeRecording: () -> Unit,
    onSendVoiceMessage: () -> Unit,
    onPreviewVoiceMessage: () -> Unit,
    onCancelRecording: () -> Unit,
    onPauseRecording: () -> Unit,
    modifier: Modifier = Modifier
) {
    val deviceConfiguration = currentDeviceConfiguration()
    val isLandscape = deviceConfiguration != DeviceConfiguration.MOBILE_PORTRAIT

    when (state) {
        VoiceRecordingState.Idle -> Unit
        is VoiceRecordingState.Recording -> VoiceRecording(
            state = state,
            isLandscape = isLandscape,
            onCancelRecording = onCancelRecording,
            onPauseRecording = onPauseRecording,
            modifier = modifier.fillMaxWidth()
        )

        is VoiceRecordingState.Paused -> VoicePlayPaused(
            state = state,
            isConnected = isConnected,
            isPlaying = isPlaying,
            playbackProgress = playbackProgress,
            isLandscape = isLandscape,
            onDiscardRecording = onDiscardRecording,
            onResumeRecording = onResumeRecording,
            onSendVoiceMessage = onSendVoiceMessage,
            onPreviewVoiceMessage = onPreviewVoiceMessage,
            modifier = modifier.fillMaxWidth()
        )

        VoiceRecordingState.Sending -> {
            Box(
                modifier = modifier
                    .fillMaxWidth()
                    .height(64.dp),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        }
    }
}

@Composable
private fun VoiceRecording(
    state: VoiceRecordingState.Recording,
    isLandscape: Boolean,
    onCancelRecording: () -> Unit,
    onPauseRecording: () -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .background(
                color = MaterialTheme.colorScheme.extended.surfaceLower,
                shape = RoundedCornerShape(16.dp)
            )
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.extended.surfaceOutline,
                shape = RoundedCornerShape(16.dp)
            )
            .padding(
                start = 16.dp,
                end = 12.dp,
                top = 8.dp,
                bottom = 8.dp
            ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = state.durationMs.formatDuration(),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.extended.textSecondary
        )
        Spacer(Modifier.width(12.dp))
        AnimatedWaveform(
            amplitudes = state.amplitudes,
            barColor = MaterialTheme.colorScheme.outlineVariant,
            maxBarHeight = if (isLandscape) 32.dp else 48.dp,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(12.dp))
        ChirpButton(
            text = stringResource(Res.string.cancel),
            onClick = onCancelRecording,
            style = ChirpButtonStyle.SECONDARY,
        )
        Spacer(Modifier.width(8.dp))
        FilledIconButton(
            onClick = onPauseRecording,
            shape = MaterialTheme.shapes.small,
            colors = IconButtonDefaults.filledIconButtonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary
            ),
            modifier = Modifier.size(44.dp)
        ) {
            Icon(
                imageVector = Icons.Default.Check,
                contentDescription = "Finish recording"
            )
        }
    }
}

@Composable
private fun VoicePlayPaused(
    state: VoiceRecordingState.Paused,
    isConnected: Boolean,
    isPlaying: Boolean,
    playbackProgress: Float,
    isLandscape: Boolean,
    onDiscardRecording: () -> Unit,
    onResumeRecording: () -> Unit,
    onSendVoiceMessage: () -> Unit,
    onPreviewVoiceMessage: () -> Unit,
    modifier: Modifier = Modifier
) {
    val containerModifier = Modifier
        .background(
            color = MaterialTheme.colorScheme.extended.surfaceLower,
            shape = RoundedCornerShape(16.dp)
        )
        .border(
            width = 1.dp,
            color = MaterialTheme.colorScheme.extended.surfaceOutline,
            shape = RoundedCornerShape(16.dp)
        )
        .padding(horizontal = 12.dp, vertical = 8.dp)

    if (isLandscape) {
        Row(
            modifier = modifier.then(containerModifier),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onDiscardRecording,
                modifier = Modifier.size(44.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = "Discard",
                    tint = MaterialTheme.colorScheme.extended.textSecondary,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(Modifier.width(4.dp))
            IconButton(
                onClick = onPreviewVoiceMessage,
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    imageVector = if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                    contentDescription = if (isPlaying) "Pause" else "Preview",
                    tint = MaterialTheme.colorScheme.extended.textSecondary
                )
            }
            Spacer(Modifier.width(8.dp))
            StaticWaveform(
                progress = playbackProgress,
                waveformData = state.waveformData,
                maxBarHeight = 32.dp,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = state.durationMs.formatDuration(),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.extended.textPrimary
            )
            Spacer(Modifier.width(8.dp))
            IconButton(
                onClick = onResumeRecording,
                modifier = Modifier.size(44.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Mic,
                    contentDescription = "Back to recording",
                    tint = MaterialTheme.colorScheme.extended.destructiveSecondaryOutline,
                    modifier = Modifier.size(28.dp)
                )
            }
            Spacer(Modifier.width(8.dp))
            FilledIconButton(
                onClick = onSendVoiceMessage,
                enabled = isConnected,
                shape = MaterialTheme.shapes.small,
                colors = IconButtonDefaults.filledIconButtonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.Send,
                    contentDescription = stringResource(Res.string.send),
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    } else {
        Column(
            modifier = modifier.then(containerModifier),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(
                    onClick = onPreviewVoiceMessage,
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(
                        imageVector = if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                        contentDescription = if (isPlaying) "Pause" else "Preview",
                        tint = MaterialTheme.colorScheme.extended.textSecondary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                StaticWaveform(
                    progress = playbackProgress,
                    waveformData = state.waveformData,
                    maxBarHeight = 44.dp,
                    modifier = Modifier
                        .weight(1f)
                )
                Text(
                    text = state.durationMs.formatDuration(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.extended.textPrimary
                )
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                IconButton(
                    onClick = onDiscardRecording,
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = "Discard",
                        tint = MaterialTheme.colorScheme.extended.textSecondary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                IconButton(
                    onClick = onResumeRecording,
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Mic,
                        contentDescription = "Back to recording",
                        tint = MaterialTheme.colorScheme.extended.destructiveSecondaryOutline,
                        modifier = Modifier.size(28.dp)
                    )
                }
                FilledIconButton(
                    onClick = onSendVoiceMessage,
                    enabled = isConnected,
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
                        imageVector = Icons.AutoMirrored.Filled.Send,
                        contentDescription = stringResource(Res.string.send),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}

@Composable
@Preview
fun VoiceRecordingMobilePortraitPreview() {
    ChirpTheme(darkTheme = true) {
        VoiceRecording(
            state = VoiceRecordingState.Recording(
                durationMs = 92000,
                amplitudes = listOf(0.1f, 0.5f, 0.3f, 0.8f, 0.4f, 0.2f, 0.7f, 0.9f, 0.5f, 0.3f)
            ),
            isLandscape = false,
            onCancelRecording = {},
            onPauseRecording = {},
            modifier = Modifier.fillMaxWidth().padding(16.dp)
        )
    }
}

@Composable
@Preview
fun VoicePlayPausedMobilePortraitPreview() {
    ChirpTheme(darkTheme = true) {
        VoicePlayPaused(
            state = VoiceRecordingState.Paused(
                durationMs = 12500,
                waveformData = List(50) { (0..100).random() / 100f },
                audioFile = File("test.mp3", "audio/mpeg", ByteArray(0))
            ),
            isConnected = true,
            isPlaying = false,
            playbackProgress = 0.5f,
            isLandscape = false,
            onDiscardRecording = {},
            onResumeRecording = {},
            onSendVoiceMessage = {},
            onPreviewVoiceMessage = {},
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        )
    }
}

@Composable
@Preview(widthDp = 640)
fun VoiceRecordingControlsNonPortraitPreview() {
    ChirpTheme {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            VoiceRecording(
                state = VoiceRecordingState.Recording(
                    durationMs = 92000,
                    amplitudes = listOf(0.1f, 0.5f, 0.3f, 0.8f, 0.4f, 0.2f, 0.7f, 0.9f, 0.5f, 0.3f)
                ),
                isLandscape = true,
                onCancelRecording = {},
                onPauseRecording = {},
                modifier = Modifier
                    .fillMaxWidth()
            )
            VoicePlayPaused(
                state = VoiceRecordingState.Paused(
                    durationMs = 12500,
                    waveformData = List(50) { (0..100).random() / 100f },
                    audioFile = File("test.mp3", "audio/mpeg", ByteArray(0))
                ),
                isConnected = true,
                isPlaying = false,
                playbackProgress = 0.5f,
                isLandscape = true,
                onDiscardRecording = {},
                onResumeRecording = {},
                onSendVoiceMessage = {},
                onPreviewVoiceMessage = {},
                modifier = Modifier
                    .fillMaxWidth()
            )
        }
    }
}
