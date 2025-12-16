package com.plcoding.core.presentation.media

import androidx.compose.runtime.Composable

@Composable
expect fun <PickerResult> rememberImagePickerLauncher(
    onError: ((String) -> Unit)? = null,
    mode: ImagePickerMode<PickerResult>,
    onResult: (PickerResult) -> Unit
): ImagePickerLauncher

fun interface ImagePickerLauncher {
    fun launch()
}