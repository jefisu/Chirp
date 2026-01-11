package com.plcoding.chat.domain.message

import com.plcoding.chat.domain.models.PendingAttachment
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result

interface MessageAttachmentRepository {

    suspend fun storeLocalAttachments(
        chatId: String,
        messageId: String,
        files: List<File>
    ): List<PendingAttachment>

    suspend fun fetchUploadInfo(
        chatId: String,
        attachments: List<PendingAttachment>
    ): Result<List<PendingAttachment>, DataError.Remote>

    suspend fun uploadAttachment(
        attachmentId: String,
        rootFile: File?
    ): EmptyResult<DataError>

    suspend fun retryAttachmentUpload(attachmentId: String): Result<PendingAttachment, DataError>

    suspend fun deleteAttachment(attachmentId: String)
    suspend fun downloadAttachment(publicUrl: String): EmptyResult<DataError.Remote>
}
