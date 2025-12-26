@file:OptIn(ExperimentalCoilApi::class)

package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import coil3.annotation.ExperimentalCoilApi
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun AttachmentsList(
    images: List<PickedImageData>,
    onRemoveClick: (PickedImageData) -> Unit,
    onImageClick: (PickedImageData) -> Unit,
    modifier: Modifier = Modifier,
) {
    val deviceConfiguration = currentDeviceConfiguration()
    val imageMinSize = 52.dp
    val arrangement = Arrangement.spacedBy(8.dp)
    val visibleImages = images.take(10)

    @Composable
    fun attachedImage(
        imageData: PickedImageData,
        modifier: Modifier = Modifier
    ) {
        AttachedImage(
            image = imageData,
            isRendered = true,
            onRemoveClick = { onRemoveClick(imageData) },
            onImageClick = { onImageClick(imageData) },
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
            images = files,
            onRemoveClick = {},
            onImageClick = {}
        )
    }

    ChirpTheme {
        content()
    }
}