package com.plcoding.chat.data.message

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkRequest
import androidx.work.workDataOf
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.models.BackgroundUploadInfo
import java.util.concurrent.TimeUnit

actual class NativeMessageAttachmentScheduler(
    private val context: Context,
    private val workManager: WorkManager
) : MessageAttachmentScheduler {

    actual override suspend fun scheduleUpload(info: BackgroundUploadInfo) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = OneTimeWorkRequestBuilder<MessageAttachmentUploadWorker>()
            .setConstraints(constraints)
            .setInputData(
                workDataOf(
                    MessageAttachmentUploadWorker.KEY_ATTACHMENT_ID to info.fileId
                )
            )
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                WorkRequest.MIN_BACKOFF_MILLIS,
                TimeUnit.MILLISECONDS
            )
            .build()

        workManager.enqueueUniqueWork(
            "upload_${info.fileId}",
            ExistingWorkPolicy.KEEP,
            request
        )
    }

    actual override fun cancel(fileId: String) {
        workManager.cancelUniqueWork("upload_$fileId")
    }
}
