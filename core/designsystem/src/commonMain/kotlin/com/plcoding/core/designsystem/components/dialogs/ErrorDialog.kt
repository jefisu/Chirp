package com.plcoding.core.designsystem.components.dialogs

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chirp.core.designsystem.generated.resources.Res
import chirp.core.designsystem.generated.resources.error_dialog_title
import chirp.core.designsystem.generated.resources.try_again
import com.plcoding.core.designsystem.components.buttons.ChirpButton
import com.plcoding.core.designsystem.components.buttons.ChirpButtonStyle
import com.plcoding.core.designsystem.theme.ChirpTheme
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.jetbrains.compose.ui.tooling.preview.PreviewParameter
import org.jetbrains.compose.ui.tooling.preview.PreviewParameterProvider

@Composable
fun ErrorDialog(
    modifier: Modifier = Modifier,
    isVisible: Boolean,
    description: String,
    onDismissClick: () -> Unit
) {
    val overlayModifier = Modifier
        .fillMaxSize()
        .background(Color.Black.copy(alpha = 0.8f))

    val contentModifier = Modifier
        .wrapContentSize()
        .size(300.dp)
        .clip(MaterialTheme.shapes.large)
        .background(MaterialTheme.colorScheme.surface)
        .padding(24.dp)

    val errorIcon = @Composable {
        val iconColor = MaterialTheme.colorScheme.error
        Icon(
            imageVector = Icons.Rounded.Close,
            contentDescription = null,
            tint = iconColor,
            modifier = Modifier
                .size(80.dp)
                .drawWithContent {
                    drawCircle(
                        color = iconColor,
                        style = Stroke(
                            width = 1.5.dp.toPx(),
                            cap = StrokeCap.Round
                        )
                    )
                    scale(0.8f) {
                        this@drawWithContent.drawContent()
                    }
                }
        )
    }

    AnimatedVisibility(
        visible = isVisible,
        enter = fadeIn(),
        exit = fadeOut()
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = modifier
                .then(overlayModifier)
                .then(contentModifier)
        ) {
            errorIcon()
            Spacer(Modifier.height(24.dp))
            Text(
                text = stringResource(Res.string.error_dialog_title).uppercase(),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(24.dp))
            ChirpButton(
                text = stringResource(Res.string.try_again),
                style = ChirpButtonStyle.DESTRUCTIVE_PRIMARY,
                onClick = onDismissClick
            )
        }
    }
}

@Preview
@Composable
private fun Preview(
    @PreviewParameter(DarkLightPreviewParam::class) isDarkTheme: Boolean
) {
    ChirpTheme(darkTheme = isDarkTheme) {
        ErrorDialog(
            isVisible = true,
            description = "Only images can be selected",
            onDismissClick = {}
        )
    }
}

private class DarkLightPreviewParam : PreviewParameterProvider<Boolean> {
    override val values: Sequence<Boolean>
        get() = sequenceOf(false, true)
}