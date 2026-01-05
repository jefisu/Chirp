package com.plcoding.chat.domain.message

import com.plcoding.chat.domain.models.BackgroundUploadInfo

interface MessageAttachmentScheduler {
    suspend fun scheduleUpload(info: BackgroundUploadInfo)
    fun cancel(fileId: String)
}
