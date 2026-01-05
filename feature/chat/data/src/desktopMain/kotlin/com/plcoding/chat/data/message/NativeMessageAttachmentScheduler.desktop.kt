package com.plcoding.chat.data.message

import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.models.BackgroundUploadInfo
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File

actual class NativeMessageAttachmentScheduler(
    private val applicationScope: CoroutineScope,
    private val messageAttachmentRepository: MessageAttachmentRepository,
    private val logger: ChirpLogger
) : MessageAttachmentScheduler {

    private val activeJobs = mutableMapOf<String, Job>()

    actual override suspend fun scheduleUpload(info: BackgroundUploadInfo) {
        val file = File(info.localFilePath)
        if (!file.exists()) {
            logger.error("File not found for upload: ${info.localFilePath}")
            return
        }

        val job = applicationScope.launch(Dispatchers.IO) {
            // Delay to ensure the file handle is released by the OS before reading, preventing potential lock contention.
            delay(200)

            logger.info("Starting upload for attachment: ${info.fileId}")
            messageAttachmentRepository
                .uploadAttachment(
                    attachmentId = info.fileId,
                    rootFile = null
                )
                .onSuccess {
                    logger.info("Upload successful for attachment: ${info.fileId}")
                }
                .onFailure { error ->
                    logger.error("Upload failed for attachment ${info.fileId}: $error")
                }

            synchronized(activeJobs) {
                activeJobs.remove(info.fileId)
            }
        }

        synchronized(activeJobs) {
            activeJobs[info.fileId]?.cancel()
            activeJobs[info.fileId] = job
        }
    }

    actual override fun cancel(fileId: String) {
        synchronized(activeJobs) {
            activeJobs[fileId]?.cancel()
            activeJobs.remove(fileId)
        }
    }
}
