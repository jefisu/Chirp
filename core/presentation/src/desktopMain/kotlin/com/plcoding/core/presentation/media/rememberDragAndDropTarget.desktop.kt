@file:OptIn(ExperimentalComposeUiApi::class)

package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.draganddrop.DragAndDropEvent
import androidx.compose.ui.draganddrop.DragAndDropTarget
import com.plcoding.core.presentation.util.UiText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import java.awt.datatransfer.DataFlavor
import java.awt.dnd.DropTargetDropEvent
import java.io.File

@Composable
actual fun <DropResult> rememberDragAndDropTargetImpl(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<DropResult>,
    onHover: (Boolean) -> Unit,
    onDrop: (DropResult) -> Unit,
    onLoading: (Boolean) -> Unit
): DragAndDropTarget {
    val scope = rememberCoroutineScope()
    return remember {
        object : DragAndDropTarget {
            override fun onStarted(event: DragAndDropEvent) {
                onHover(true)
            }

            override fun onEnded(event: DragAndDropEvent) {
                onHover(false)
            }

            override fun onDrop(event: DragAndDropEvent): Boolean {
                val nativeEvent = event.nativeEvent as DropTargetDropEvent
                val fileList = nativeEvent
                    .transferable
                    .getTransferData(DataFlavor.javaFileListFlavor)
                        as List<*>

                val hasInvalidExtension = fileList.any { (it as File).extension !in allowedImageExtensions }
                if (hasInvalidExtension) {
                    onError?.invoke(ImagePickerError.InvalidMimeType.toUiText())
                    return false
                }

                onLoading(true)
                scope.launch(Dispatchers.IO) {
                    val pickedImages = fileList
                        .map {
                            async {
                                (it as File).toPickedImageData()
                            }
                        }
                        .awaitAll()
                        .filterNotNull()

                    @Suppress("UNCHECKED_CAST")
                    val result = when (mode) {
                        ImagePickerMode.Single -> pickedImages.firstOrNull()
                        is ImagePickerMode.Multiple -> pickedImages.take(mode.maxItems)
                    } as DropResult

                    onLoading(false)
                    onDrop(result)
                }

                return true
            }
        }
    }
}