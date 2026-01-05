@file:OptIn(ExperimentalCoilApi::class)

package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.paint
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil3.annotation.ExperimentalCoilApi
import coil3.compose.AsyncImagePainter
import coil3.compose.rememberAsyncImagePainter
import com.plcoding.core.designsystem.theme.ChirpBase0
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun AttachmentsList(
    pickedImages: List<PickedImageData>,
    onRemoveClick: (PickedImageData) -> Unit,
    onImageClick: (PickedImageData) -> Unit,
    modifier: Modifier = Modifier,
) {
    val deviceConfiguration = currentDeviceConfiguration()
    val imageMinSize = 52.dp
    val arrangement = Arrangement.spacedBy(8.dp)
    val visibleImages = pickedImages.take(10)

    @Composable
    fun attachedImage(
        imageData: PickedImageData,
        modifier: Modifier = Modifier
    ) {
        ImageAttachment(
            painter = rememberAsyncImagePainter(imageData.bytes),
            onCloseClick = { onRemoveClick(imageData) },
            onClick = { onImageClick(imageData) },
            modifier = modifier
        )
    }

    if (deviceConfiguration == DeviceConfiguration.MOBILE_PORTRAIT) {
        LazyVerticalGrid(
            columns = GridCells.Adaptive(imageMinSize),
            horizontalArrangement = arrangement,
            verticalArrangement = arrangement,
            modifier = modifier
        ) {
            items(visibleImages) { imageData ->
                attachedImage(
                    imageData = imageData,
                    modifier = Modifier.aspectRatio(1f)
                )
            }
        }
    } else {
        FlowRow(
            horizontalArrangement = arrangement,
            verticalArrangement = arrangement,
            modifier = modifier
        ) {
            visibleImages.forEach { imageData ->
                attachedImage(
                    imageData = imageData,
                    modifier = Modifier
                        .sizeIn(maxWidth = imageMinSize, maxHeight = imageMinSize)
                        .aspectRatio(1f)
                )
            }
        }
    }
}

@Composable
private fun ImageAttachment(
    painter: AsyncImagePainter,
    onCloseClick: () -> Unit,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val inPreviewMode = LocalInspectionMode.current
    val state by painter.state.collectAsStateWithLifecycle()

    Box(
        modifier = modifier
            .size(52.dp)
            .clip(MaterialTheme.shapes.medium)
            .paint(
                painter = painter,
                contentScale = ContentScale.Crop,
            )
            .clickable { onClick() }
            .drawWithContent {
                if (inPreviewMode) drawRect(Color.Red)
                drawContent()
            }
    ) {
        if (state is AsyncImagePainter.State.Loading) {
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .background(Color.Black.copy(alpha = 0.05f))
            ) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .scale(0.6f)
                )
            }
        }
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(4.dp)
                .clip(MaterialTheme.shapes.extraSmall)
                .background(ChirpBase0)
                .size(20.dp)
                .paint(
                    painter = rememberVectorPainter(Icons.Rounded.Close),
                    colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.extended.destructiveSecondaryOutline)
                )
                .clickable(
                    onClick = onCloseClick
                )
        )
    }
}

@Preview
@Composable
private fun Preview() {
    val files = List(8) {
        PickedImageData(
            name = "Attachment",
            bytes = byteArrayOf(),
            mimeType = "image/jpeg",
            height = 0,
            width = 0,
        )
    }

    val content = @Composable {
        AttachmentsList(
            pickedImages = files,
            onRemoveClick = {},
            onImageClick = {}
        )
    }

    ChirpTheme {
        content()
    }
}
