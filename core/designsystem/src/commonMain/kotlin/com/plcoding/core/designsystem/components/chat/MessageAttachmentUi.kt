package com.plcoding.core.designsystem.components.chat

data class MessageAttachmentUi(
    val id: String,
    val url: String,
    val type: MessageAttachmentTypeUi,
    val status: MessageAttachmentUploadStatusUi,
    val contentBytes: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as MessageAttachmentUi

        return !listOf(
            id != other.id,
            url != other.url,
            type != other.type,
            status != other.status,
            when {
                contentBytes == null -> other.contentBytes != null
                other.contentBytes == null -> true
                else -> !contentBytes.contentEquals(other.contentBytes)
            }
        ).any { it }
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + url.hashCode()
        result = 31 * result + (contentBytes?.contentHashCode() ?: 0)
        result = 31 * result + type.hashCode()
        result = 31 * result + status.hashCode()
        return result
    }
}

enum class MessageAttachmentTypeUi {
    IMAGE,
}

enum class MessageAttachmentUploadStatusUi {
    PENDING,
    UPLOADING,
    UPLOADED,
    FAILED
}
