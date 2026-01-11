package com.plcoding.core.designsystem.components.dialogs

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.zIndex
import com.plcoding.core.presentation.util.currentDeviceConfiguration

@Composable
fun ChirpAdaptiveDialog(
    isVisible: Boolean,
    onDismiss: () -> Unit,
    content: @Composable () -> Unit
) {
    val configuration = currentDeviceConfiguration()
    if (isVisible) {
        if (configuration.isWideScreen) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(0.4f))
                    .zIndex(1f)
                    .pointerInput(Unit) {
                        detectTapGestures {
                            onDismiss()
                        }
                    },
                contentAlignment = Alignment.Center
            ) {
                content()
            }
        } else {
            Dialog(
                onDismissRequest = onDismiss,
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                )
            ) {
                content()
            }
        }
    }
}