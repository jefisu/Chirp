package com.plcoding.core.presentation.util

import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp

data class ImageSizingResult(
    val contentScale: ContentScale,
    val modifier: Modifier
)

fun calculateImageSizing(
    intrinsicSize: Size,
    deviceConfiguration: DeviceConfiguration,
    applyPadding: Boolean = true
): ImageSizingResult {
    return when {
        deviceConfiguration == DeviceConfiguration.MOBILE_LANDSCAPE -> {
            ImageSizingResult(
                contentScale = ContentScale.FillHeight,
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(if (applyPadding) 8.dp else 0.dp)
            )
        }

        intrinsicSize.height >= intrinsicSize.width -> {
            ImageSizingResult(
                contentScale = ContentScale.FillHeight,
                modifier = Modifier
                    .sizeIn(maxHeight = 600.dp)
                    .fillMaxHeight()
                    .padding(if (applyPadding) 16.dp else 0.dp)
            )
        }

        else -> {
            ImageSizingResult(
                contentScale = ContentScale.FillWidth,
                modifier = Modifier
                    .sizeIn(maxWidth = 700.dp)
                    .fillMaxWidth()
                    .padding(if (applyPadding) 16.dp else 0.dp)
            )
        }
    }
}
