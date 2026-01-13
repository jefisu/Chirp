package com.plcoding.chat.domain.models

enum class MessageAttachmentType(val mimeType: String) {
    IMAGE("image/jpeg");

    companion object {
        fun fromMimeType(mimeType: String): MessageAttachmentType? {
            return when (mimeType) {
                "image/jpeg", "image/jpg", "image/png", "image/webp" -> IMAGE
                else -> null
            }
        }
    }
}