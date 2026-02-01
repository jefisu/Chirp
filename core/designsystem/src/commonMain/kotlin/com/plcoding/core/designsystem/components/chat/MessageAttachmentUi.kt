package com.plcoding.core.designsystem.components.chat

sealed interface MessageAttachmentUi {
    val id: String
    val url: String
    val status: MessageAttachmentUploadStatusUi

    class Image(
        override val id: String,
        override val url: String,
        override val status: MessageAttachmentUploadStatusUi,
        val contentBytes: ByteArray? = null,
    ) : MessageAttachmentUi
}

enum class MessageAttachmentUploadStatusUi {
    PENDING,
    UPLOADING,
    UPLOADED,
    FAILED,
}
