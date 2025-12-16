@file:OptIn(ExperimentalCoilApi::class)

package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import coil3.annotation.ExperimentalCoilApi
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.presentation.media.PickedImageData
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun AttachmentsList(
    images: List<PickedImageData>,
    onRemoveClick: (PickedImageData) -> Unit,
    modifier: Modifier = Modifier,
    renderingImage: PickedImageData? = null
) {
    LazyVerticalGrid(
        columns = GridCells.Adaptive(52.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = modifier
    ) {
        renderingImage?.let { image ->
            item {
                AttachedImage(
                    image = image,
                    isRendered = false,
                    onRemoveClick = { onRemoveClick(image) },
                    modifier = Modifier
                        .widthIn(max = 280.dp)
                        .aspectRatio(1f)
                )
            }
        }
        items(images) { image ->
            AttachedImage(
                image = image,
                isRendered = true,
                onRemoveClick = { onRemoveClick(image) },
                modifier = Modifier.aspectRatio(1f)
            )
        }
    }
}

@Preview
@Composable
private fun Preview() {
    val files = List(2) {
        PickedImageData(
            name = "Attachment",
            bytes = byteArrayOf(),
            mimeType = "image/jpeg"
        )
    }

    val content = @Composable {
        AttachmentsList(
            images = files,
            renderingImage = files.first(),
            onRemoveClick = {}
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