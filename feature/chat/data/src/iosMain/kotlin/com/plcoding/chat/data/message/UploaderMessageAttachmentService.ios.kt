package com.plcoding.chat.data.message

import com.plcoding.chat.domain.message.MessageAttachmentService
import com.plcoding.chat.domain.models.AttachmentUploadInfo
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.Result
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import platform.Foundation.NSTemporaryDirectory

actual class UploaderMessageAttachmentService(
    private val uploadManager: IosBackgroundUploadManager
) : MessageAttachmentService {

   actual override suspend fun getUploadFilesUrl(
        chatId: String,
        files: List<File>
    ): Result<List<AttachmentUploadInfo>, DataError.Remote> {
       TODO("Not implemented")
    }

    actual override suspend fun uploadFile(
        attachmentId: String,
        uploadUrl: String,
        binaryData: ByteArray,
        headers: Map<String, String>,
        onSuccess: suspend () -> Unit,
        onFailure: suspend () -> Unit
    ) {
        val tempFilePath = "${NSTemporaryDirectory()}$attachmentId.tmp"
        val path = Path(tempFilePath)

        try {
            SystemFileSystem.sink(path).buffered().use { sink ->
                sink.write(binaryData)
            }

            uploadManager.scheduleTask(
                attachmentId = attachmentId,
                filePath = tempFilePath,
                uploadUrl = uploadUrl,
                headers = headers,
                onSuccess = onSuccess,
                onFailure = onFailure
            )
        } catch (e: Exception) {
            onFailure()
        }
    }

    actual override suspend fun downloadAttachment(url: String): Result<ByteArray, DataError.Remote> {
        TODO("Not implemented")
    }
}
