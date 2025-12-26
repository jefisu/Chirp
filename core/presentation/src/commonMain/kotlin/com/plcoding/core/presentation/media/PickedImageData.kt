package com.plcoding.core.presentation.media

import kotlin.time.Clock

data class PickedImageData(
    val bytes: ByteArray,
    val mimeType: String?,
    val height: Int,
    val width: Int,
    val extension: String? = mimeType?.substringAfter("/"),
    val name: String = "Chirp_image_${Clock.System.now()}.$extension"
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PickedImageData

        if (!bytes.contentEquals(other.bytes)) return false
        if (mimeType != other.mimeType) return false
        if (name != other.name) return false

        return true
    }

    override fun hashCode(): Int {
        var result = bytes.contentHashCode()
        result = 31 * result + (mimeType?.hashCode() ?: 0)
        result = 31 * result + name.hashCode()
        return result
    }
}