package com.plcoding.core.presentation.media

sealed interface ImagePickerMode<PickerResult> {
    data object Single : ImagePickerMode<PickedImageData?>
    data class Multiple(val maxItems: Int) : ImagePickerMode<List<PickedImageData>>

    fun consumeResult(
        result: PickerResult,
        onConsumed: (PickerResult) -> Unit
    ) {
        onConsumed(result)
    }
}