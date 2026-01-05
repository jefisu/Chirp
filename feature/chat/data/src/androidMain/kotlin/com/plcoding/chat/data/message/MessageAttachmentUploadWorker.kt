package com.plcoding.chat.data.message

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess

class MessageAttachmentUploadWorker(
    context: Context,
    params: WorkerParameters,
    private val messageAttachmentRepository: MessageAttachmentRepository,
    private val logger: ChirpLogger
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val attachmentId = inputData.getString(KEY_ATTACHMENT_ID) ?: return Result.failure()

        messageAttachmentRepository
            .uploadAttachment(attachmentId, rootFile = null)
            .onSuccess {
                return Result.success()
            }
            .onFailure { error ->
                logger.error("Failed to upload attachment with ID: $attachmentId. Error: $error")
            }

        return Result.failure()
    }

    companion object Companion {
        const val KEY_ATTACHMENT_ID = "attachment_id"
    }
}