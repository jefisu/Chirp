package com.plcoding.chat.presentation.profile.mediapicker

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.draganddrop.DragAndDropEvent
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.media.PickedImageData
import com.plcoding.core.presentation.util.UiText

// Drag and drop not supported on mobile platforms
@Composable
actual fun rememberDragAndDropTarget(
    onError: ((UiText) -> Unit)?,
    onHover: (Boolean) -> Unit,
    onDrop: (PickedImageData) -> Unit
): DragAndDropTarget {
    return remember {
        object : DragAndDropTarget {
            override fun onDrop(event: DragAndDropEvent): Boolean {
                return false
            }
        }
    }
}