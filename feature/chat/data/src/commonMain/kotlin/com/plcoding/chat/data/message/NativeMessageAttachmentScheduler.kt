package com.plcoding.chat.data.message

import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.models.BackgroundUploadInfo

expect class NativeMessageAttachmentScheduler : MessageAttachmentScheduler {
    override suspend fun scheduleUpload(info: BackgroundUploadInfo)
    override fun cancel(fileId: String)
}
