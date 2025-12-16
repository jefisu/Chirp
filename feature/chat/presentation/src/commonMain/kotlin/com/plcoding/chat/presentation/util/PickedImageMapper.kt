package com.plcoding.chat.presentation.util

import com.plcoding.core.domain.media.File
import com.plcoding.core.presentation.media.PickedImageData

fun PickedImageData.toFile(): File {
    return File(
        name = name,
        mimeType = mimeType,
        bytes = bytes,
    )
}