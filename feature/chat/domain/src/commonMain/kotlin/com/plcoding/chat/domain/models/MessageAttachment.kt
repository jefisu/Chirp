package com.plcoding.chat.domain.models

data class MessageAttachment(
    val id: String,
    val url: String,
    val type: MessageAttachmentType,
    val status: MessageAttachmentUploadStatus = MessageAttachmentUploadStatus.PENDING,
)
