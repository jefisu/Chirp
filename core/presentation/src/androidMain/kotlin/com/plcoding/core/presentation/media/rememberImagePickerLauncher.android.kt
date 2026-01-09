package com.plcoding.core.presentation.media

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.util.fastMap
import com.plcoding.core.presentation.util.UiText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch

@Composable
actual fun <PickerResult> rememberImagePickerLauncherImpl(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val parser = remember { ContentUriParser(context) }

    val singleImagePickerLauncher = rememberSingleImagePickerLauncher(
        scope = scope,
        parser = parser,
        mode = mode,
        onLoading = onLoading,
        onResult = onResult
    )

    val multipleImagePickerLauncher = rememberMultipleImagesPickerLauncher(
        scope = scope,
        parser = parser,
        mode = mode,
        onLoading = onLoading,
        onResult = onResult
    )

    return remember {
        ImagePickerLauncher {
            val mediaType = PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
            when (mode) {
                ImagePickerMode.Single -> singleImagePickerLauncher.launch(mediaType)
                is ImagePickerMode.Multiple -> multipleImagePickerLauncher.launch(mediaType)
            }
        }
    }
}

@Composable
private fun <PickerResult> rememberSingleImagePickerLauncher(
    scope: CoroutineScope,
    parser: ContentUriParser,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
    onResult: (PickerResult) -> Unit
) = run {
    @Suppress("UNCHECKED_CAST")
    rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { contentUri ->
        if (contentUri == null) {
            mode.consumeResult(
                result = null as PickerResult,
                onConsumed = onResult
            )
            return@rememberLauncherForActivityResult
        }

        onLoading(true)
        scope.launch {
            val dimensions = parser.getDimensions(contentUri)
            val pickedImage = PickedImageData(
                bytes = parser.readUri(contentUri) ?: run {
                    onLoading(false)
                    mode.consumeResult(
                        result = null as PickerResult,
                        onConsumed = onResult
                    )
                    return@launch
                },
                mimeType = parser.getMimeType(contentUri),
                width = dimensions.first,
                height = dimensions.second
            ).let { image ->
                parser.getFileName(contentUri)?.let { image.copy(name = it) } ?: image
            }

            onLoading(false)
            mode.consumeResult(
                result = pickedImage as PickerResult,
                onConsumed = onResult
            )
        }
    }
}

@Composable
private fun <PickerResult> rememberMultipleImagesPickerLauncher(
    scope: CoroutineScope,
    parser: ContentUriParser,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
    onResult: (PickerResult) -> Unit
) = run {
    @Suppress("UNCHECKED_CAST")
    rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickMultipleVisualMedia(
            maxItems = (mode as? ImagePickerMode.Multiple)?.maxItems ?: 10
        )
    ) { contentUris ->
        if (contentUris.isEmpty()) {
            mode.consumeResult(
                result = emptyList<PickedImageData>() as PickerResult,
                onConsumed = onResult
            )
            return@rememberLauncherForActivityResult
        }

        onLoading(true)
        scope.launch {
            val pickedImages = contentUris
                .fastMap { contentUri ->
                    async {
                        val dimensions = parser.getDimensions(contentUri)
                        PickedImageData(
                            bytes = parser.readUri(contentUri) ?: return@async null,
                            mimeType = parser.getMimeType(contentUri),
                            width = dimensions.first,
                            height = dimensions.second
                        ).let { image ->
                            parser.getFileName(contentUri)?.let { image.copy(name = it) } ?: image
                        }
                    }
                }
                .awaitAll()
                .filterNotNull()

            onLoading(false)
            mode.consumeResult(
                result = pickedImages as PickerResult,
                onConsumed = onResult
            )
        }
    }
}
