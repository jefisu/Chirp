package com.plcoding.core.presentation.media

import chirp.core.presentation.generated.resources.Res
import chirp.core.presentation.generated.resources.error_invalid_images
import com.plcoding.core.domain.util.Error
import com.plcoding.core.presentation.util.UiText

enum class ImagePickerError : Error {
    InvalidMimeType;

    fun toUiText(): UiText = when (this) {
        InvalidMimeType -> UiText.Resource(Res.string.error_invalid_images)
    }
}