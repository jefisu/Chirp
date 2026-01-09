package com.plcoding.core.presentation.media

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Image
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.zIndex
import chirp.core.presentation.generated.resources.Res
import chirp.core.presentation.generated.resources.optimizing_for_upload
import chirp.core.presentation.generated.resources.processing_image
import com.plcoding.core.presentation.util.UiText
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import kotlinx.coroutines.delay
import org.jetbrains.compose.resources.stringResource

@Composable
fun <PickerResult> rememberImagePickerLauncher(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<PickerResult>,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher {
    var isLoading by remember { mutableStateOf(false) }
    ProcessingOverlay(isLoading)

    return rememberImagePickerLauncherImpl(
        onError = onError,
        mode = mode,
        onResult = onResult,
        onLoading = { isLoading = it }
    )
}

@Composable
expect fun <PickerResult> rememberImagePickerLauncherImpl(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher

fun interface ImagePickerLauncher {
    fun launch()
}

@Composable
fun ProcessingOverlay(isLoading: Boolean) {
    var shouldShowLoading by remember { mutableStateOf(false) }

    LaunchedEffect(isLoading) {
        if (isLoading) {
            delay(200)
            shouldShowLoading = true
        } else {
            shouldShowLoading = false
        }
    }

    if (shouldShowLoading) {
        val configuration = currentDeviceConfiguration()
        if (configuration.isWideScreen) {
            val disabledTouchModifier = if (isLoading) {
                Modifier.pointerInput(Unit) { }
            } else Modifier

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(0.4f))
                    .zIndex(1f)
                    .then(disabledTouchModifier),
                contentAlignment = Alignment.Center
            ) {
                ImageProcessing()
            }
        } else {
            Dialog(
                onDismissRequest = {},
                properties = DialogProperties(
                    dismissOnBackPress = false,
                    dismissOnClickOutside = false,
                ),
            ) {
                ImageProcessing()
            }
        }
    }
}

@Composable
private fun ImageProcessing(
    modifier: Modifier = Modifier
) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier
                .padding(24.dp)
                .widthIn(min = 200.dp, max = 300.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = Icons.Default.Image,
                contentDescription = null,
                modifier = Modifier
                    .size(48.dp)
                    .padding(bottom = 16.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(
                text = stringResource(Res.string.processing_image),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(Res.string.optimizing_for_upload),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(24.dp))
            LinearProgressIndicator(
                modifier = Modifier
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp))
            )
        }
    }
}
