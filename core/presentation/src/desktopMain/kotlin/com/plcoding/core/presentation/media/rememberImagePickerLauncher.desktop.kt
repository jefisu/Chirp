package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import chirp.core.presentation.generated.resources.Res
import chirp.core.presentation.generated.resources.select_a_image
import com.plcoding.core.presentation.util.UiText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.jetbrains.compose.resources.stringResource
import java.awt.FileDialog
import java.awt.Frame
import java.awt.Image
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.FilenameFilter
import java.nio.file.Files
import javax.imageio.ImageIO
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.math.max

@Composable
actual fun <PickerResult> rememberImagePickerLauncherImpl(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
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
                
                val pickedImages = pickImages(
                    fileDialogTitle = dialogTitle,
                    maxItems = maxItems,
                    onLoading = onLoading
                )

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
    maxItems: Int,
    onLoading: (Boolean) -> Unit
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

    if (files.isEmpty()) return emptyList()

    onLoading(true)
    
    val result = withContext(Dispatchers.Default) {
        files.mapNotNull { file ->
            try {
                // supports JPG, PNG, GIF, BMP
                var image = ImageIO.read(file)

                if (image == null) {
                    val fileSize = file.length()
                    val safetyLimit = 30 * 1024 * 1024L // 30 MB
                    
                    if (fileSize <= safetyLimit) {
                         val bytes = Files.readAllBytes(file.toPath())
                         val mimeType = when(file.name.substringAfterLast(".").lowercase()) {
                             "webp" -> "image/webp"
                             "png" -> "image/png"
                             "jpg", "jpeg" -> "image/jpeg"
                             else -> "image/*"
                         }
                         
                         return@mapNotNull PickedImageData(
                            bytes = bytes,
                            mimeType = mimeType,
                            width = 0,
                            height = 0,
                            name = file.name
                        )
                    } else {
                        // Skip huge unsupported files to prevent OOM
                        println("Skipping large unsupported file: ${file.name}")
                        return@mapNotNull null
                    }
                }
                
                val maxDimension = 2500
                val width = image.width
                val height = image.height
                
                if (width > maxDimension || height > maxDimension) {
                    val scale = maxDimension.toDouble() / max(width, height)
                    val newWidth = (width * scale).toInt()
                    val newHeight = (height * scale).toInt()
                    
                    val resized = BufferedImage(newWidth, newHeight, image.type)
                    val g = resized.createGraphics()
                    g.drawImage(image.getScaledInstance(newWidth, newHeight, Image.SCALE_SMOOTH), 0, 0, null)
                    g.dispose()
                    image = resized
                }
                
                val outputStream = ByteArrayOutputStream()
                val format = file.name.substringAfterLast(".", "jpg")
                val targetFormat = if (format.lowercase() in listOf("png", "webp")) format else "jpg"
                
                if (!ImageIO.write(image, targetFormat, outputStream)) {
                     ImageIO.write(image, "jpg", outputStream)
                }
                
                val bytes = outputStream.toByteArray()
                
                PickedImageData(
                    bytes = bytes,
                    mimeType = "image/$targetFormat",
                    width = image.width,
                    height = image.height,
                    name = file.name
                )
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }
    }
    
    onLoading(false)
    return result
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
