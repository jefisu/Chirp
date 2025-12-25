package com.plcoding.chat.presentation.profile.mediapicker

import androidx.compose.runtime.Composable
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.UiText

@Composable
expect fun rememberDragAndDropTarget(
    onError: ((UiText) -> Unit)? = null,
    onHover: (Boolean) -> Unit,
    onDrop: (PickedImageData) -> Unit
): DragAndDropTarget