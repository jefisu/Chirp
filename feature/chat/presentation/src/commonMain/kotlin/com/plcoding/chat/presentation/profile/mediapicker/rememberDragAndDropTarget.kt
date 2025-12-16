package com.plcoding.chat.presentation.profile.mediapicker

import androidx.compose.runtime.Composable
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.media.PickedImageData

@Composable
expect fun rememberDragAndDropTarget(
    onHover: (Boolean) -> Unit,
    onDrop: (PickedImageData) -> Unit
): DragAndDropTarget