package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Composable
fun StaticWaveform(
    progress: Float,
    waveformData: List<Float>?,
    modifier: Modifier = Modifier,
    barSpacing: Dp = 2.dp,
    minBarHeight: Dp = 4.dp,
    maxBarHeight: Dp = 32.dp,
    playedColor: Color = MaterialTheme.colorScheme.primary,
    unplayedColor: Color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
    maxBars: Int = 40
) {
    val effectiveWaveformData = remember(waveformData, maxBars) {
        val data = waveformData?.takeIf { it.isNotEmpty() } ?: List(maxBars) { 0.1f }

        List(maxBars) { i ->
            val bucketStartFloat = i.toFloat() * data.size / maxBars
            val bucketEndFloat = (i + 1).toFloat() * data.size / maxBars

            val start = bucketStartFloat.toInt().coerceIn(0, data.size - 1)
            val end = bucketEndFloat.toInt().coerceIn(0, data.size)

            if (start < end) {
                // Downsampling
                data.subList(start, end).maxOrNull() ?: 0.1f
            } else {
                // Upsampling
                data[start.coerceAtMost(data.size - 1)]
            }
        }
    }

    Canvas(
        modifier = modifier
            .height(maxBarHeight)
    ) {
        val barSpacingPx = barSpacing.toPx()
        val minHeightPx = minBarHeight.toPx()
        val maxHeightPx = maxBarHeight.toPx()
        val centerY = size.height / 2

        val barCount = effectiveWaveformData.size

        val totalSpacing = barSpacingPx * (barCount - 1)
        val availableWidthForBars = size.width - totalSpacing
        val dynamicBarWidthPx =
            if (barCount > 0) (availableWidthForBars / barCount).coerceAtLeast(1f) else 2.dp.toPx()

        fun DrawScope.drawWaveformBars(color: Color) {
            effectiveWaveformData.forEachIndexed { index, amplitude ->
                val barHeight = minHeightPx + (amplitude * (maxHeightPx - minHeightPx))
                val x = index * (dynamicBarWidthPx + barSpacingPx)
                val y = centerY - (barHeight / 2)

                drawRoundRect(
                    color = color,
                    topLeft = Offset(x, y),
                    size = Size(dynamicBarWidthPx, barHeight),
                    cornerRadius = CornerRadius(dynamicBarWidthPx / 2, dynamicBarWidthPx / 2)
                )
            }
        }

        drawWaveformBars(unplayedColor)

        clipRect(right = size.width * progress.coerceIn(0f, 1f)) {
            drawWaveformBars(playedColor)
        }
    }
}
