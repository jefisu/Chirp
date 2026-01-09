@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import com.plcoding.core.domain.media.resize
import com.plcoding.core.presentation.util.UiText
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.refTo
import kotlinx.cinterop.useContents
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import platform.Foundation.NSData
import platform.Foundation.NSItemProvider
import platform.PhotosUI.PHPickerConfiguration
import platform.PhotosUI.PHPickerConfigurationSelectionOrdered
import platform.PhotosUI.PHPickerFilter
import platform.PhotosUI.PHPickerResult
import platform.PhotosUI.PHPickerViewController
import platform.PhotosUI.PHPickerViewControllerDelegateProtocol
import platform.UIKit.UIApplication
import platform.UIKit.UIImage
import platform.UIKit.UIImageJPEGRepresentation
import platform.UniformTypeIdentifiers.UTType
import platform.darwin.NSObject
import platform.darwin.dispatch_get_main_queue
import platform.darwin.dispatch_group_create
import platform.darwin.dispatch_group_enter
import platform.darwin.dispatch_group_leave
import platform.darwin.dispatch_group_notify
import platform.posix.memcpy
import kotlin.math.min

@Composable
actual fun <PickerResult> rememberImagePickerLauncherImpl(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<PickerResult>,
    onLoading: (Boolean) -> Unit,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher {
    val scope = rememberCoroutineScope()
    
    val delegate = remember {
        object : NSObject(), PHPickerViewControllerDelegateProtocol {
            override fun picker(picker: PHPickerViewController, didFinishPicking: List<*>) {
                picker.dismissViewControllerAnimated(true, null)

                val results = didFinishPicking.filterIsInstance<PHPickerResult>()
                if (results.isEmpty()) {
                    return
                }

                onLoading(true)
                val dispatchGroup = dispatch_group_create()
                val imageDataList = mutableListOf<PickedImageData>()

                for (result in results) {
                    dispatch_group_enter(dispatchGroup)
                    
                    processPickerResult(
                        result = result,
                        onSuccess = { pickedData ->
                            imageDataList.add(pickedData)
                            dispatch_group_leave(dispatchGroup)
                        },
                        onFailure = {
                            dispatch_group_leave(dispatchGroup)
                        }
                    )
                }

                dispatch_group_notify(dispatchGroup, dispatch_get_main_queue()) {
                    onLoading(false)
                    @Suppress("UNCHECKED_CAST")
                    val finalResult = when (mode) {
                        ImagePickerMode.Single -> imageDataList.firstOrNull()
                        is ImagePickerMode.Multiple -> imageDataList
                    } as PickerResult
                    
                    mode.consumeResult(
                        result = finalResult,
                        onConsumed = onResult
                    )
                }
            }
            
            private fun processPickerResult(
                result: PHPickerResult,
                onSuccess: (PickedImageData) -> Unit,
                onFailure: () -> Unit
            ) {
                val itemProvider = result.itemProvider
                val typeIdentifiers = itemProvider.registeredTypeIdentifiers
                val primaryType = typeIdentifiers.firstOrNull() as? String

                if (primaryType == null) {
                    onFailure()
                    return
                }

                val mimeType = UTType.typeWithIdentifier(primaryType)?.preferredMIMEType
                if (mimeType == null) {
                    onFailure()
                    return
                }

                itemProvider.loadDataRepresentationForTypeIdentifier(primaryType) { nsData, _ ->
                    if (nsData == null) {
                        onFailure()
                        return@loadDataRepresentationForTypeIdentifier
                    }

                    scope.launch {
                        val pickedData = processImageNsData(nsData, itemProvider)
                        if (pickedData != null) {
                            onSuccess(pickedData)
                        } else {
                            onFailure()
                        }
                    }
                }
            }
        }
    }

    return remember {
        ImagePickerLauncher {
            val maxItems = when (mode) {
                is ImagePickerMode.Multiple -> mode.maxItems
                ImagePickerMode.Single -> 1
            }
            val pickerViewController = PHPickerViewController(
                configuration = PHPickerConfiguration().apply {
                    setSelectionLimit(maxItems.toLong())
                    setFilter(PHPickerFilter.imagesFilter)
                    setSelection(PHPickerConfigurationSelectionOrdered)
                }
            )
            pickerViewController.delegate = delegate

            UIApplication.sharedApplication.keyWindow?.rootViewController?.presentViewController(
                pickerViewController,
                true,
                null
            )
        }
    }
}

private suspend fun processImageNsData(nsData: NSData, itemProvider: NSItemProvider): PickedImageData? {
    return withContext(Dispatchers.Default) {
        try {
            val image = UIImage(data = nsData)
            val originalWidth = image.size.useContents { width }
            val originalHeight = image.size.useContents { height }

            // Max dimension to prevent OOM on large images (e.g. 4K/8K)
            val maxDimension = 2500.0

            val finalImage = if (originalWidth > maxDimension || originalHeight > maxDimension) {
                val scale = min(maxDimension / originalWidth, maxDimension / originalHeight)
                image.resize(originalWidth * scale, originalHeight * scale)
            } else {
                image
            }

            val jpegData = UIImageJPEGRepresentation(finalImage, 0.9) ?: nsData

            val bytes = ByteArray(jpegData.length.toInt())
            memcpy(bytes.refTo(0), jpegData.bytes, jpegData.length)

            val finalWidth = finalImage.size.useContents { width }.toInt()
            val finalHeight = finalImage.size.useContents { height }.toInt()

            val name = itemProvider.suggestedName?.substringBeforeLast(".")?.let { "$it.jpg" } 
                ?: "image.jpg"

            PickedImageData(
                bytes = bytes,
                mimeType = "image/jpeg",
                width = finalWidth,
                height = finalHeight,
                name = name
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
