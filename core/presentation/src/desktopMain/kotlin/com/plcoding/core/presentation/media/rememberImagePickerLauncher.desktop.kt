package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import chirp.core.presentation.generated.resources.Res
import chirp.core.presentation.generated.resources.select_a_image
import com.plcoding.core.presentation.util.UiText
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.jetbrains.compose.resources.stringResource
import java.awt.FileDialog
import java.awt.Frame
import java.io.FilenameFilter
import javax.swing.SwingUtilities
import kotlin.coroutines.resume

@Composable
actual fun <PickerResult> rememberImagePickerLauncher(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<PickerResult>,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher {
    val scope = rememberCoroutineScope()
    val dialogTitle = stringResource(Res.string.select_a_image)

    return remember(dialogTitle) {
        ImagePickerLauncher {
            scope.launch {
                val maxItems = when (mode) {
                    is ImagePickerMode.Multiple -> mode.maxItems
                    ImagePickerMode.Single -> 1
                }
                val pickedImages = pickImages(dialogTitle, maxItems)

                val hasInvalidImageFiles = pickedImages.any { it.extension !in allowedImageExtensions }
                if (hasInvalidImageFiles) {
                    onError?.invoke(ImagePickerError.InvalidMimeType.toUiText())
                    return@launch
                }

                @Suppress("UNCHECKED_CAST")
                mode.consumeResult(
                    result = when (mode) {
                        ImagePickerMode.Single -> pickedImages.firstOrNull()
                        is ImagePickerMode.Multiple -> pickedImages
                    } as PickerResult,
                    onConsumed = onResult
                )
            }
        }
    }
}

private suspend fun pickImages(
    fileDialogTitle: String,
    maxItems: Int
): List<PickedImageData> {
    val files = suspendCancellableCoroutine { continuation ->
        var fileDialog: FileDialog? = null

        continuation.invokeOnCancellation {
            SwingUtilities.invokeLater {
                fileDialog?.dispose()
            }
        }

        SwingUtilities.invokeLater {
            try {
                fileDialog = createFileDialog(fileDialogTitle, maxItems)

                val selectedFiles = fileDialog
                    .files
                    .take(maxItems)
                    .filterNotNull()

                continuation.resume(selectedFiles)
            } catch (_: Exception) {
                continuation.resume(emptyList())
            }
        }
    }

    return files.mapNotNull { it.toPickedImageData() }
}

private fun createFileDialog(
    fileDialogTitle: String,
    maxItems: Int
): FileDialog {
    return FileDialog(
        Frame(),
        fileDialogTitle,
        FileDialog.LOAD
    ).apply {
        filenameFilter = FilenameFilter { _, name ->
            allowedImageExtensions.any { name.endsWith(it) }
        }
        isMultipleMode = maxItems > 1
        isVisible = true
    }
}