package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.models.MessageAttachment
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.core.designsystem.components.chat.MessageAttachmentTypeUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUploadStatusUi

fun MessageAttachment.toMessageAttachmentUi(): MessageAttachmentUi {
    return MessageAttachmentUi(
        id = id,
        url = url,
        type = type.toMessageAttachmentTypeUi(),
        status = status.toMessageAttachmentUploadStatusUi()
    )
}

fun MessageAttachmentType.toMessageAttachmentTypeUi(): MessageAttachmentTypeUi {
    return when (this) {
        MessageAttachmentType.IMAGE -> MessageAttachmentTypeUi.IMAGE
    }
}

fun MessageAttachmentUploadStatus.toMessageAttachmentUploadStatusUi(): MessageAttachmentUploadStatusUi {
    return when (this) {
        MessageAttachmentUploadStatus.PENDING -> MessageAttachmentUploadStatusUi.PENDING
        MessageAttachmentUploadStatus.UPLOADING -> MessageAttachmentUploadStatusUi.UPLOADING
        MessageAttachmentUploadStatus.UPLOADED -> MessageAttachmentUploadStatusUi.UPLOADED
        MessageAttachmentUploadStatus.FAILED -> MessageAttachmentUploadStatusUi.FAILED
    }
}
