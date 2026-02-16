package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.you
import com.plcoding.chat.domain.models.ChatMessageDeliveryStatus
import com.plcoding.chat.presentation.util.formatDuration
import com.plcoding.core.designsystem.components.chat.ChatBubbleShape
import com.plcoding.core.designsystem.components.chat.TrianglePosition
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VoiceMessageBubble(
    durationMs: Long,
    isPlaying: Boolean,
    isLoading: Boolean,
    currentPosition: Long,
    waveformData: List<Float>,
    sender: String,
    formattedDateTime: String,
    trianglePosition: TrianglePosition,
    color: Color = MaterialTheme.colorScheme.extended.surfaceHigher,
    onPlayPauseClick: () -> Unit,
    modifier: Modifier = Modifier,
    accentColor: Color = MaterialTheme.colorScheme.primary,
    triangleSize: Dp = 16.dp,
    onLongClick: (() -> Unit)? = null,
    messageStatus: @Composable (() -> Unit)? = null,
) {
    val padding = 12.dp
    val progress = if (durationMs > 0) {
        (currentPosition.toFloat() / durationMs).coerceIn(0f, 1f)
    } else {
        0f
    }

    Column(
        modifier = modifier
            .widthIn(max = 320.dp)
            .clip(
                ChatBubbleShape(
                    trianglePosition = trianglePosition,
                    triangleSize = triangleSize
                )
            )
            .background(color)
            .then(
                if (onLongClick != null) {
                    Modifier.combinedClickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(
                            color = MaterialTheme.colorScheme.extended.surfaceOutline
                        ),
                        onLongClick = onLongClick,
                        onClick = {}
                    )
                } else Modifier
            )
            .padding(
                start = if (trianglePosition == TrianglePosition.LEFT) {
                    padding + triangleSize
                } else padding,
                end = if (trianglePosition == TrianglePosition.RIGHT) {
                    padding + triangleSize
                } else padding,
                top = padding,
                bottom = padding
            ),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = sender,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.extended.textSecondary,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(20.dp))
            Text(
                text = formattedDateTime,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.extended.textSecondary,
            )
        }
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                modifier = Modifier
                    .clip(CircleShape)
                    .background(accentColor),
                contentAlignment = Alignment.Center,
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp,
                    )
                } else {
                    IconButton(
                        onClick = onPlayPauseClick,
                        modifier = Modifier.size(44.dp),
                    ) {
                        Icon(
                            imageVector = if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                            contentDescription = if (isPlaying) "Pause" else "Play",
                            tint = MaterialTheme.colorScheme.onPrimary,
                        )
                    }
                }
            }
            StaticWaveform(
                progress = progress,
                waveformData = waveformData.takeIf { it.isNotEmpty() },
                maxBarHeight = 24.dp,
                playedColor = accentColor,
                unplayedColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
                modifier = Modifier.weight(1f),
            )
            Text(
                text = if (currentPosition == 0L) {
                    durationMs.formatDuration()
                } else {
                    currentPosition.formatDuration()
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        }
        messageStatus?.invoke()
    }
}

@Preview
@Composable
private fun VoiceMessageBubblePreview() {
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp),
        modifier = Modifier.width(300.dp)
    ) {
        ChirpTheme {
            VoiceMessageBubble(
                durationMs = 120000,
                isPlaying = false,
                isLoading = false,
                currentPosition = 30000,
                waveformData = List(50) { (0..100).random() / 100f },
                onPlayPauseClick = {},
                trianglePosition = TrianglePosition.LEFT,
                formattedDateTime = "Friday, Ago 20",
                sender = "John"
            )
        }
        ChirpTheme(darkTheme = true) {
            VoiceMessageBubble(
                durationMs = 45000,
                isPlaying = true,
                isLoading = false,
                currentPosition = 15000,
                waveformData = List(50) { (0..100).random() / 100f },
                onPlayPauseClick = {},
                trianglePosition = TrianglePosition.RIGHT,
                formattedDateTime = "Friday, Ago 20",
                sender = stringResource(Res.string.you),
                messageStatus = {
                    MessageStatus(ChatMessageDeliveryStatus.SENT)
                }
            )
        }
    }
}
