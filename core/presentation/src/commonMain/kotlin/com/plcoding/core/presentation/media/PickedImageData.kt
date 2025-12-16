package com.plcoding.core.presentation.media

import kotlin.time.Clock

data class PickedImageData(
    val bytes: ByteArray,
    val mimeType: String?,
    val extension: String? = mimeType?.substringAfter("/"),
    val name: String = "Chirp_image_${Clock.System.now()}.$extension"
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        other as PickedImageData
        return bytes.contentEquals(other.bytes) && mimeType == other.mimeType
    }

    override fun hashCode(): Int {
        var result = bytes.contentHashCode()
        result = 31 * result + (mimeType?.hashCode() ?: 0)
        result = 31 * result + name.hashCode()
        return result
    }
}