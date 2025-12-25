package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable
import com.plcoding.core.presentation.util.UiText

@Composable
expect fun <PickerResult> rememberImagePickerLauncher(
    onError: ((UiText) -> Unit)? = null,
    mode: ImagePickerMode<PickerResult>,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher

fun interface ImagePickerLauncher {
    fun launch()
}