@file:OptIn(ExperimentalCoilApi::class)

package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.unit.dp
import coil3.annotation.ExperimentalCoilApi
import coil3.compose.SubcomposeAsyncImage
import com.plcoding.core.designsystem.components.icon.AttachFileOutlinedIcon
import com.plcoding.core.designsystem.theme.ChirpBase0
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.presentation.media.PickedImageData
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.jetbrains.compose.ui.tooling.preview.PreviewParameter
import org.jetbrains.compose.ui.tooling.preview.PreviewParameterProvider

@Composable
fun AttachedImage(
    image: PickedImageData,
    onRemoveClick: () -> Unit,
    modifier: Modifier = Modifier,
    isRendered: Boolean = true,
    renderingProgress: (() -> Float)? = null
) {
    val previewModifier = if (LocalInspectionMode.current) {
        Modifier.background(Color.Red)
    } else Modifier

    val closeIcon = @Composable {
        Icon(
            imageVector = Icons.Rounded.Close,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.extended.destructiveSecondaryOutline
        )
    }

    val attachedImage = @Composable {
        Box {
            SubcomposeAsyncImage(
                model = image.bytes,
                contentDescription = image.name,
                contentScale = ContentScale.Crop,
                modifier = modifier
                    .sizeIn(minWidth = 52.dp, minHeight = 52.dp)
                    .clip(MaterialTheme.shapes.medium)
                    .then(previewModifier),
                loading = {
                    CircularProgressIndicator(
                        modifier = Modifier.scale(0.7f)
                    )
                }
            )
            FilledIconButton(
                onClick = onRemoveClick,
                shape = MaterialTheme.shapes.extraSmall,
                colors = IconButtonDefaults.filledIconButtonColors(
                    containerColor = ChirpBase0,
                ),
                modifier = Modifier
                    .size(20.dp)
                    .align(Alignment.TopEnd)
                    .offset((-4).dp, 4.dp),
                content = closeIcon
            )
        }
    }

    val renderingImage = @Composable {
        val renderingColor = MaterialTheme.colorScheme.onSurface
        Row(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            modifier = modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .background(MaterialTheme.colorScheme.surface)
                .drawWithContent {
                    drawContent()
                    renderingProgress?.invoke()?.let { progress ->
                        drawRect(
                            color = renderingColor.copy(alpha = 0.1f),
                            size = size.copy(width = size.width * progress)
                        )
                    }
                }
                .padding(4.dp)
        ) {
            AttachFileOutlinedIcon(
                enabled = false
            )
            Text(
                text = image.name,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.extended.textSecondary,
                maxLines = 2,
                modifier = Modifier.weight(1f)
            )
            IconButton(
                onClick = onRemoveClick,
                content = closeIcon
            )
        }
    }

    if (isRendered) {
        attachedImage()
    } else {
        renderingImage()
    }
}

@Preview
@Composable
private fun Preview(
    @PreviewParameter(PreviewParam::class) isRendered: Boolean
) {
    val renderingProgress by animateFloatAsState(0f)
    val content = @Composable {
        AttachedImage(
            image = PickedImageData(
                name = "Latest design screenshot",
                bytes = byteArrayOf(),
                mimeType = "image/jpg"
            ),
            isRendered = isRendered,
            onRemoveClick = {},
            renderingProgress = { renderingProgress },
            modifier = Modifier.widthIn(max = 300.dp)
        )
    }

    Column {
        ChirpTheme {
            content()
        }
        Spacer(Modifier.height(8.dp))
        ChirpTheme(darkTheme = true) {
            content()
        }
    }
}

private class PreviewParam : PreviewParameterProvider<Boolean> {
    override val values: Sequence<Boolean>
        get() = sequenceOf(true, false)
}