package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import coil3.compose.AsyncImage
import com.plcoding.core.designsystem.theme.ChirpBase0
import com.plcoding.core.designsystem.theme.ChirpBase900
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration

@Composable
fun ImagePreviewDialog(
    image: PickedImageData,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val deviceConfiguration = currentDeviceConfiguration()

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false
        )
    ) {
        val (contentScale, imageModifier) = when {
            deviceConfiguration == DeviceConfiguration.MOBILE_LANDSCAPE -> {
                ContentScale.FillHeight to Modifier
                    .fillMaxHeight()
                    .padding(8.dp)
            }

            image.height >= image.width -> {
                ContentScale.FillHeight to Modifier
                    .sizeIn(maxHeight = 600.dp)
                    .fillMaxHeight()
                    .padding(16.dp)
            }

            else -> {
                ContentScale.FillWidth to Modifier
                    .sizeIn(maxWidth = 900.dp)
                    .fillMaxWidth()
                    .padding(16.dp)
            }
        }
        val iconPadding = when (deviceConfiguration) {
            DeviceConfiguration.MOBILE_LANDSCAPE -> 20.dp
            else -> 28.dp
        }

        Box(modifier = modifier) {
            AsyncImage(
                model = image.bytes,
                contentDescription = image.name,
                contentScale = contentScale,
                modifier = imageModifier
                    .clip(MaterialTheme.shapes.medium)
                    .border(
                        width = 4.dp,
                        color = ChirpBase0,
                        shape = MaterialTheme.shapes.medium
                    )
                    .drawWithContent {
                        drawContent()
                        drawRect(color = Color.Black.copy(alpha = 0.2f))
                    }
            )
            Icon(
                imageVector = Icons.Rounded.Close,
                contentDescription = null,
                tint = ChirpBase900,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(iconPadding)
                    .size(44.dp)
                    .clip(MaterialTheme.shapes.medium)
                    .background(ChirpBase0)
                    .clickable {
                        onDismiss()
                    }
                    .scale(0.6f)
            )
        }
    }
}