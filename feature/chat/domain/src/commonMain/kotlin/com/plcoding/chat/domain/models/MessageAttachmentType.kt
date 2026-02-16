package com.plcoding.chat.domain.models

enum class MessageAttachmentType(val mimeType: String) {
    IMAGE("image/jpeg"),
    AUDIO("audio/m4a");

    companion object {
        fun fromMimeType(mimeType: String): MessageAttachmentType? {
            return when {
                mimeType.startsWith("image/") -> IMAGE
                mimeType.startsWith("audio/") -> AUDIO
                else -> null
            }
        }
    }
}