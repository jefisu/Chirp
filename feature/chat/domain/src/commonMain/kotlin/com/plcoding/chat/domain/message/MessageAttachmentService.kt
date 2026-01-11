package com.plcoding.chat.domain.message

import com.plcoding.chat.domain.models.AttachmentUploadInfo
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.Result

interface MessageAttachmentService {
    suspend fun getUploadFilesUrl(
        chatId: String,
        files: List<File>
    ): Result<List<AttachmentUploadInfo>, DataError.Remote>

    suspend fun uploadFile(
        attachmentId: String,
        uploadUrl: String,
        binaryData: ByteArray,
        headers: Map<String, String>,
        onSuccess: suspend () -> Unit,
        onFailure: suspend () -> Unit
    )

    suspend fun downloadAttachment(url: String): Result<ByteArray, DataError.Remote>
}
