package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.models.MessageAttachment
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUploadStatusUi

fun MessageAttachment.toMessageAttachmentUi(): MessageAttachmentUi {
    return when (type) {
        MessageAttachmentType.IMAGE -> MessageAttachmentUi.Image(
            id = id,
            url = url,
            status = status.toMessageAttachmentUploadStatusUi(),
        )

        MessageAttachmentType.AUDIO -> MessageAttachmentUi.Audio(
            id = id,
            url = url,
            status = status.toMessageAttachmentUploadStatusUi(),
        )
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
