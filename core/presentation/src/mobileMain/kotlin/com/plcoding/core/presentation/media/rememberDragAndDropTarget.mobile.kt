package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.draganddrop.DragAndDropEvent
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.util.UiText

// Drag and drop not supported on mobile platforms
@Composable
actual fun <DropResult> rememberDragAndDropTargetImpl(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<DropResult>,
    onHover: (Boolean) -> Unit,
    onDrop: (DropResult) -> Unit,
    onLoading: (Boolean) -> Unit
): DragAndDropTarget {
    return remember {
        object : DragAndDropTarget {
            override fun onDrop(event: DragAndDropEvent): Boolean {
                return false
            }
        }
    }
}