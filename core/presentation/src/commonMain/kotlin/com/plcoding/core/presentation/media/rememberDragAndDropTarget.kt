package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.util.UiText

@Composable
fun <DropResult> rememberDragAndDropTarget(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<DropResult>,
    onHover: (Boolean) -> Unit,
    onDrop: (DropResult) -> Unit
): DragAndDropTarget {
    var isLoading by remember { mutableStateOf(false) }
    ProcessingOverlay(isLoading)

    return rememberDragAndDropTargetImpl(
        onError = onError,
        mode = mode,
        onHover = onHover,
        onDrop = onDrop,
        onLoading = { isLoading = it }
    )
}

@Composable
expect fun <DropResult> rememberDragAndDropTargetImpl(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<DropResult>,
    onHover: (Boolean) -> Unit,
    onDrop: (DropResult) -> Unit,
    onLoading: (Boolean) -> Unit
): DragAndDropTarget
