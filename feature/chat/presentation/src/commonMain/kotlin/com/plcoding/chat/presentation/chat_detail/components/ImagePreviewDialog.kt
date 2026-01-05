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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.paint
import androidx.compose.ui.draw.scale
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import coil3.compose.AsyncImagePainter
import com.plcoding.core.designsystem.theme.ChirpBase0
import com.plcoding.core.designsystem.theme.ChirpBase900
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import net.engawapg.lib.zoomable.rememberZoomState
import net.engawapg.lib.zoomable.zoomable

@Composable
fun ImagePreviewDialog(
    painter: AsyncImagePainter,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val size = painter.intrinsicSize
    val deviceConfiguration = currentDeviceConfiguration()

    var zoomScale by rememberSaveable { mutableStateOf(1f) }
    val zoomState = rememberZoomState(initialScale = zoomScale)

    val (contentScale, imageModifier) = when {
        deviceConfiguration == DeviceConfiguration.MOBILE_LANDSCAPE -> {
            ContentScale.FillHeight to Modifier
                .fillMaxHeight()
                .padding(8.dp)
        }

        size.height >= size.width -> {
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

    LifecycleEventEffect(event = Lifecycle.Event.ON_STOP) {
        zoomScale = zoomState.scale
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false
        )
    ) {
        Box(
            modifier = modifier
        ) {
            Box(
                modifier = imageModifier
                    .clip(MaterialTheme.shapes.medium)
                    .border(
                        width = 4.dp,
                        color = ChirpBase0,
                        shape = MaterialTheme.shapes.medium
                    )
                    .zoomable(zoomState)
                    .paint(
                        painter = painter,
                        contentScale = contentScale
                    )
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
            if (zoomState.scale > 1.0f) {
                Text(
                    text = "${(zoomState.scale * 100).toInt()}%",
                    style = MaterialTheme.typography.bodyLarge,
                    color = ChirpBase900,
                    modifier = Modifier
                        .align(Alignment.TopStart)
                        .padding(iconPadding)
                        .clip(MaterialTheme.shapes.medium)
                        .background(ChirpBase0)
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                )
            }
        }
    }
}