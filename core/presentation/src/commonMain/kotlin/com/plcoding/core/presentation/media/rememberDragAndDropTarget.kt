package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.util.UiText

@Composable
expect fun <DropResult> rememberDragAndDropTarget(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<DropResult>,
    onHover: (Boolean) -> Unit,
    onDrop: (DropResult) -> Unit
): DragAndDropTarget