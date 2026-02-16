package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Composable
fun AnimatedWaveform(
    amplitudes: List<Float>,
    modifier: Modifier = Modifier,
    barCount: Int = 40,
    barWidth: Dp = 2.dp,
    barSpacing: Dp = 2.dp,
    minBarHeight: Dp = 4.dp,
    maxBarHeight: Dp = 32.dp,
    barColor: Color = MaterialTheme.colorScheme.primary
) {
    val recentAmplitudes = remember(barCount) {
        mutableStateListOf<Float>().apply {
            repeat(barCount) { add(0f) }
        }
    }

    LaunchedEffect(amplitudes) {
        val next = if (amplitudes.size >= barCount) {
            amplitudes.takeLast(barCount)
        } else {
            List(barCount - amplitudes.size) { 0f } + amplitudes
        }
        next.forEachIndexed { index, value ->
            if (index < recentAmplitudes.size) {
                recentAmplitudes[index] = value
            }
        }
    }

    val animatedAmplitudes = (0 until barCount).map { index ->
        animateFloatAsState(
            targetValue = recentAmplitudes[index].coerceIn(0f, 1f),
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioNoBouncy,
                stiffness = Spring.StiffnessMediumLow
            ),
            label = "waveform_bar_$index"
        )
    }

    Canvas(
        modifier = modifier
            .height(maxBarHeight)
    ) {
        val barSpacingPx = barSpacing.toPx()
        val minHeightPx = minBarHeight.toPx()
        val maxHeightPx = maxBarHeight.toPx()
        val centerY = size.height / 2

        val totalSpacing = barSpacingPx * (barCount - 1)
        val availableWidthForBars = size.width - totalSpacing

        val dynamicBarWidthPx =
            if (barCount > 0) availableWidthForBars / barCount else barWidth.toPx()

        animatedAmplitudes.forEachIndexed { index, state ->
            val amplitude = state.value
            val barHeight = minHeightPx + (amplitude * (maxHeightPx - minHeightPx))
            val x = index * (dynamicBarWidthPx + barSpacingPx)
            val y = centerY - (barHeight / 2)

            drawRoundRect(
                color = barColor,
                topLeft = Offset(x, y),
                size = Size(dynamicBarWidthPx, barHeight),
                cornerRadius = CornerRadius(dynamicBarWidthPx / 2, dynamicBarWidthPx / 2)
            )
        }
    }
}
