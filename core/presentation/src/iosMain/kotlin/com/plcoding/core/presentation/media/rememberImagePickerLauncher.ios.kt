@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import com.plcoding.core.presentation.util.UiText
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.refTo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import platform.PhotosUI.PHPickerConfiguration
import platform.PhotosUI.PHPickerConfigurationSelectionOrdered
import platform.PhotosUI.PHPickerFilter
import platform.PhotosUI.PHPickerResult
import platform.PhotosUI.PHPickerViewController
import platform.PhotosUI.PHPickerViewControllerDelegateProtocol
import platform.UIKit.UIApplication
import platform.UniformTypeIdentifiers.UTType
import platform.darwin.NSObject
import platform.darwin.dispatch_get_main_queue
import platform.darwin.dispatch_group_create
import platform.darwin.dispatch_group_enter
import platform.darwin.dispatch_group_leave
import platform.darwin.dispatch_group_notify
import platform.posix.memcpy

@Composable
actual fun <PickerResult> rememberImagePickerLauncher(
    onError: ((UiText) -> Unit)?,
    mode: ImagePickerMode<PickerResult>,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher {
    val scope = rememberCoroutineScope()
    val delegate = remember {
        object : NSObject(), PHPickerViewControllerDelegateProtocol {
            override fun picker(picker: PHPickerViewController, didFinishPicking: List<*>) {
                picker.dismissViewControllerAnimated(true, null)

                val results = didFinishPicking.filterIsInstance<PHPickerResult>()
                val dispatchGroup = dispatch_group_create()
                val imageDataList = mutableListOf<PickedImageData>()

                for (result in results) {
                    dispatch_group_enter(dispatchGroup)

                    val itemProvider = result.itemProvider
                    val typeIdentifiers = itemProvider.registeredTypeIdentifiers
                    val primaryType = typeIdentifiers.firstOrNull() as? String

                    if (primaryType == null) {
                        dispatch_group_leave(dispatchGroup)
                        continue
                    }

                    val mimeType = UTType
                        .typeWithIdentifier(primaryType)
                        ?.preferredMIMEType

                    if (mimeType == null) {
                        dispatch_group_leave(dispatchGroup)
                        continue
                    }

                    itemProvider.loadDataRepresentationForTypeIdentifier(
                        typeIdentifier = primaryType
                    ) { nsData, _ ->
                        if (nsData == null) return@loadDataRepresentationForTypeIdentifier

                        scope.launch {
                            val bytes = ByteArray(nsData.length.toInt())

                            withContext(Dispatchers.Default) {
                                memcpy(bytes.refTo(0), nsData.bytes, nsData.length)
                            }

                            imageDataList.add(
                                PickedImageData(
                                    bytes = bytes,
                                    mimeType = mimeType
                                ).also { image ->
                                    itemProvider.suggestedName?.let { image.copy(name = it) }
                                }
                            )
                            dispatch_group_leave(dispatchGroup)
                        }
                    }
                }

                dispatch_group_notify(dispatchGroup, dispatch_get_main_queue()) {
                    @Suppress("UNCHECKED_CAST")
                    mode.consumeResult(
                        result = when (mode) {
                            ImagePickerMode.Single -> imageDataList.firstOrNull()
                            is ImagePickerMode.Multiple -> imageDataList
                        } as PickerResult,
                        onConsumed = onResult
                    )
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