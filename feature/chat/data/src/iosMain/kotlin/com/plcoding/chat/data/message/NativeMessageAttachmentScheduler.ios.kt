package com.plcoding.chat.data.message

import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.models.BackgroundUploadInfo

actual class NativeMessageAttachmentScheduler(
    private val repository: MessageAttachmentRepository,
    private val uploadManager: IosBackgroundUploadManager
) : MessageAttachmentScheduler {

    actual override suspend fun scheduleUpload(info: BackgroundUploadInfo) {
        repository.uploadAttachment(
            attachmentId = info.fileId,
            rootFile = null
        )
    }

    actual override fun cancel(fileId: String) {
        uploadManager.cancelTask(fileId)
    }
}
