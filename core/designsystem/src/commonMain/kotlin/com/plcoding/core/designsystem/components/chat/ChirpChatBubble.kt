package com.plcoding.core.designsystem.components.chat

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil3.compose.AsyncImagePainter
import coil3.compose.rememberAsyncImagePainter
import com.plcoding.core.designsystem.theme.ChirpBase100
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun ChirpChatBubble(
    messageContent: String?,
    sender: String,
    formattedDateTime: String,
    attachments: List<MessageAttachmentUi>,
    trianglePosition: TrianglePosition,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.extended.surfaceHigher,
    messageStatus: @Composable (() -> Unit)? = null,
    triangleSize: Dp = 16.dp,
    onLongClick: (() -> Unit)? = null,
    onAttachmentClick: ((MessageAttachmentUi) -> Unit)? = null,
    onAttachmentLongClick: ((MessageAttachmentUi) -> Unit)? = null,
) {
    val padding = 12.dp

    Column(
        modifier = modifier
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
            .clip(
                ChatBubbleShape(
                    trianglePosition = trianglePosition,
                    triangleSize = triangleSize
                )
            )
            .background(color)
            .padding(
                start = if (trianglePosition == TrianglePosition.LEFT) {
                    padding + triangleSize
                } else padding,
                end = if (trianglePosition == TrianglePosition.RIGHT) {
                    padding + triangleSize
                } else padding,
                top = padding,
                bottom = padding
            )
            .width(IntrinsicSize.Max),
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
        messageContent?.let {
            Text(
                text = messageContent,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.extended.textPrimary,
                modifier = Modifier
                    .fillMaxWidth()
            )
        }
        AttachedFilesContent(
            attachments = attachments,
            onAttachmentClick = onAttachmentClick,
            onAttachmentLongClick = onAttachmentLongClick,
        )
        messageStatus?.invoke()
    }
}

@Composable
private fun AttachedFilesContent(
    attachments: List<MessageAttachmentUi>,
    onAttachmentClick: ((MessageAttachmentUi) -> Unit)?,
    onAttachmentLongClick: ((MessageAttachmentUi) -> Unit)?,
    modifier: Modifier = Modifier,
    limitVisible: Int = 5,
    itemSize: Dp = 52.dp,
) {
    val imageAttachments = attachments.filterIsInstance<MessageAttachmentUi.Image>()

    val totalImageCount = imageAttachments.size
    val showMoreIndicator = totalImageCount > limitVisible
    val visibleImageCount = if (showMoreIndicator) limitVisible - 1 else totalImageCount
    val remainingAttachments = totalImageCount - visibleImageCount

    val inPreviewMode = LocalInspectionMode.current
    val attachmentModifier = Modifier
        .size(itemSize)
        .clip(MaterialTheme.shapes.medium)
        .drawWithContent {
            if (inPreviewMode) drawRect(color = Color.Red)
            drawContent()
        }

    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = modifier
    ) {
        if (imageAttachments.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                imageAttachments.take(visibleImageCount).forEach { attachment ->
                    Box(contentAlignment = Alignment.Center) {
                        ChatImageAttachment(
                            url = attachment.url,
                            contentBytes = attachment.contentBytes,
                            isUploading = attachment.status != MessageAttachmentUploadStatusUi.UPLOADED,
                            modifier = attachmentModifier,
                            onClick = { onAttachmentClick?.invoke(attachment) },
                            onLongClick = { onAttachmentLongClick?.invoke(attachment) }
                        )

                        when (attachment.status) {
                            MessageAttachmentUploadStatusUi.UPLOADING -> {
                                CircularProgressIndicator(
                                    modifier = Modifier.scale(0.5f),
                                    color = Color.White
                                )
                            }

                            MessageAttachmentUploadStatusUi.FAILED -> {
                                Icon(
                                    imageVector = Icons.Default.Upload,
                                    contentDescription = "Retry upload",
                                    tint = Color.White,
                                    modifier = Modifier
                                        .align(Alignment.Center)
                                        .scale(0.8f)
                                )
                            }

                            else -> Unit
                        }
                    }
                }

                if (showMoreIndicator) {
                    val previewAttachment = imageAttachments[visibleImageCount]
                    ChatMoreAttachmentsIndicator(
                        previewAttachment = previewAttachment,
                        remainingCount = remainingAttachments,
                        modifier = attachmentModifier,
                    )
                }
            }
        }
    }
}

@Composable
private fun ChatImageAttachment(
    url: String?,
    contentBytes: ByteArray?,
    isUploading: Boolean,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null,
) {
    val remotePainter = rememberAsyncImagePainter(url)
    val remotePainterState by remotePainter.state.collectAsStateWithLifecycle()

    Box(modifier = modifier) {
        when (remotePainterState) {
            is AsyncImagePainter.State.Success -> {
                Image(
                    painter = remotePainter,
                    contentDescription = url,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .matchParentSize()
                        .combinedClickable(
                            enabled = !isUploading,
                            onClick = { onClick?.invoke() },
                            onLongClick = { onLongClick?.invoke() }
                        )
                )
            }

            is AsyncImagePainter.State.Loading -> {
                CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier
                        .matchParentSize()
                        .darkenOverlay(enabled = true)
                        .scale(0.5f)
                )
            }

            else -> {
                Box(
                    modifier = Modifier
                        .matchParentSize()
                        .darkenOverlay(
                            enabled = true,
                            alpha = if (isSystemInDarkTheme()) 0.4f else 0.15f
                        )
                        .clickable { remotePainter.restart() }
                ) {
                    Icon(
                        imageVector = Icons.Default.CloudDownload,
                        contentDescription = "Retry download",
                        tint = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.align(Alignment.Center)
                    )
                }
            }
        }
        contentBytes?.let {
            Image(
                painter = rememberAsyncImagePainter(it),
                contentDescription = url,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .matchParentSize()
                    .darkenOverlay(enabled = isUploading)
            )
        }
    }
}

@Composable
private fun ChatMoreAttachmentsIndicator(
    previewAttachment: MessageAttachmentUi.Image,
    remainingCount: Int,
    modifier: Modifier = Modifier,
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
    ) {
        Image(
            painter = rememberAsyncImagePainter(previewAttachment.url),
            contentDescription = previewAttachment.url,
            contentScale = ContentScale.Crop,
            modifier = Modifier.matchParentSize(),
        )
        Image(
            painter = rememberAsyncImagePainter(previewAttachment.contentBytes),
            contentDescription = previewAttachment.url,
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .matchParentSize()
                .darkenOverlay(enabled = true, alpha = 0.65f)
        )
        Text(
            text = "+$remainingCount",
            style = MaterialTheme.typography.bodyLarge,
            color = ChirpBase100
        )
    }
}

private fun Modifier.darkenOverlay(
    enabled: Boolean,
    alpha: Float = 0.4f
) = this
    .drawWithContent {
        drawContent()
        if (enabled) {
            drawRect(color = Color.Black.copy(alpha))
        }
    }

@Composable
@Preview
fun ChirpChatBubbleLeftPreview() {
    ChirpTheme(darkTheme = true) {
        ChirpChatBubble(
            messageContent = "Hello world, this is a longer message that hopefully spans" +
                    "over multiple lines so we can see how the preview would look like for that as well.",
            sender = "Philipp",
            formattedDateTime = "Friday 2:20pm",
            trianglePosition = TrianglePosition.LEFT,
            color = MaterialTheme.colorScheme.extended.accentGreen,
            attachments = emptyList(),
        )
    }
}

@Composable
@Preview
fun ChirpChatBubbleRightPreview() {
    val attachedFiles = ('a'..'f').map {
        MessageAttachmentUi.Image(
            id = it.toString(),
            url = it.toString(),
            status = MessageAttachmentUploadStatusUi.UPLOADED
        )
    }

    ChirpTheme {
        ChirpChatBubble(
            messageContent = "Hello world, this is a longer message that hopefully spans" +
                    "over multiple lines so we can see how the preview would look like for that as well.",
            sender = "Philipp",
            formattedDateTime = "Friday 2:20pm",
            trianglePosition = TrianglePosition.RIGHT,
            attachments = attachedFiles,
        )
    }
}
