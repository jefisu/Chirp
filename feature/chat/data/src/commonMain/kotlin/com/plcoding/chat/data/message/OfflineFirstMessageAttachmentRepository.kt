@file:OptIn(ExperimentalUuidApi::class)

package com.plcoding.chat.data.message

import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.PendingAttachmentEntity
import com.plcoding.chat.domain.message.MessageAttachmentRepository
import com.plcoding.chat.domain.message.MessageAttachmentService
import com.plcoding.chat.domain.models.MessageAttachment
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.chat.domain.models.PendingAttachment
import com.plcoding.core.data.database.safeDatabaseUpdate
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.media.ImageCompressor
import com.plcoding.core.domain.media.StorageDestination
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.asEmptyResult
import com.plcoding.core.domain.util.map
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class OfflineFirstMessageAttachmentRepository(
    private val database: ChirpChatDatabase,
    private val messageAttachmentService: MessageAttachmentService,
    private val imageCompressor: ImageCompressor,
    private val fileStore: FileStore,
    private val logger: ChirpLogger
) : MessageAttachmentRepository {

    override suspend fun storeLocalAttachments(
        chatId: String,
        messageId: String,
        files: List<File>
    ): List<PendingAttachment> {
        return files.mapNotNull { file ->
            val mimeType = file.mimeType ?: return@mapNotNull null
            val uniqueFileName = "${Uuid.random()}_${file.name}"
            val localPath = fileStore.getFilePath(uniqueFileName)

            fileStore.saveFile(file.bytes, uniqueFileName)

            val attachmentId = Uuid.random().toString()
            val type = MessageAttachmentType.fromMimeType(mimeType) ?: run {
                logger.error("Invalid mime type: $mimeType from File: ${file.name}")
                return emptyList()
            }
            val messageAttachment = MessageAttachment(
                id = attachmentId,
                url = localPath,
                type = type,
                status = MessageAttachmentUploadStatus.PENDING
            )

            PendingAttachment(
                messageAttachment = messageAttachment,
                uploadUrl = "",
                uploadExpiresAt = Instant.fromEpochMilliseconds(0),
                file = file,
                publicUrl = ""
            )
        }
    }

    override suspend fun fetchUploadInfo(
        chatId: String,
        attachments: List<PendingAttachment>
    ): Result<List<PendingAttachment>, DataError.Remote> {
        if (attachments.isEmpty()) return Result.Success(emptyList())

        val files = attachments.map { it.file }
        return messageAttachmentService
            .getUploadFilesUrl(chatId, files)
            .map { uploadInfo ->
                uploadInfo.mapNotNull { uploadInfo ->
                    val originalAttachment = attachments
                        .find { it.file.name == uploadInfo.originalFile.name }
                        ?: return@mapNotNull null

                    originalAttachment.copy(
                        uploadUrl = uploadInfo.uploadUrl,
                        uploadExpiresAt = uploadInfo.expiresAt,
                        publicUrl = uploadInfo.publicUrl
                    )
                }
            }
    }

    override suspend fun uploadAttachment(
        attachmentId: String,
        rootFile: File?
    ): EmptyResult<DataError> {
        return safeDatabaseUpdate {
            val preparedData = compressAndPrepare(attachmentId, rootFile)
                ?: return Result.Failure(DataError.Local.COMPRESSION_FAILED)

            messageAttachmentService.uploadFile(
                attachmentId = attachmentId,
                uploadUrl = preparedData.pending.uploadUrl,
                binaryData = preparedData.compressedBytes,
                headers = mapOf("Content-Type" to preparedData.mimeType),
                onSuccess = {
                    database.messageAttachmentDao.updateUploadedAttachment(
                        attachmentId = attachmentId,
                        url = preparedData.pending.publicUrl,
                        pendingAttachmentDao = database.pendingAttachmentDao
                    )
                    fileStore.deleteFile(preparedData.pending.localPath)
                },
                onFailure = {
                    handleUploadFailure(attachmentId, preparedData.pending.localPath)
                }
            )
        }
    }

    override suspend fun retryAttachmentUpload(attachmentId: String): Result<PendingAttachment, DataError> {
        val pendingUpload = database.pendingAttachmentDao
            .getPendingAttachmentById(attachmentId)
            ?: return Result.Failure(DataError.Local.NOT_FOUND)

        val isExpired = Clock.System.now().toEpochMilliseconds() > pendingUpload.expiresAt
        if (isExpired) {
            val retryResult = retryExpiredUpload(pendingUpload)
            if (retryResult is Result.Failure) {
                return Result.Failure(retryResult.error)
            }

            val updatedPendingUpload = database.pendingAttachmentDao
                .getPendingAttachmentById(attachmentId)
                ?: return Result.Failure(DataError.Local.NOT_FOUND)

            return mapToPendingAttachment(updatedPendingUpload)
        }

        return mapToPendingAttachment(pendingUpload)
    }

    override suspend fun deleteAttachment(attachmentId: String) {
        val pendingUpload = database.pendingAttachmentDao
            .getPendingAttachmentById(attachmentId)
            ?: return

        fileStore.deleteFile(pendingUpload.localPath)
    }

    override suspend fun downloadAttachment(publicUrl: String): EmptyResult<DataError.Remote> {
        return messageAttachmentService
            .downloadAttachment(publicUrl)
            .onSuccess { bytes ->
                val extension = publicUrl.substringAfterLast(".")
                val fileName = "Chirp_image_${Uuid.random()}.$extension"
                fileStore.saveFile(bytes, fileName, StorageDestination.GALLERY)
            }
            .asEmptyResult()
    }

    private fun mapToPendingAttachment(entity: PendingAttachmentEntity): Result<PendingAttachment, DataError> {
        val mimeType = getMimeTypeFromUrl(entity.publicUrl)
        val fileName = entity.localPath.substringAfterLast("/")
        val currentPath = fileStore.getFilePath(fileName)

        val file = File(
            name = fileName,
            mimeType = mimeType,
            bytes = byteArrayOf()
        )

        val type = MessageAttachmentType.fromMimeType(mimeType) ?: run {
            logger.error("Invalid mime type: $mimeType from URL: ${entity.publicUrl}")
            return Result.Failure(DataError.Local.NOT_FOUND)
        }
        val messageAttachment = MessageAttachment(
            id = entity.attachmentId,
            url = currentPath,
            type = type,
            status = MessageAttachmentUploadStatus.PENDING
        )

        return Result.Success(
            PendingAttachment(
                messageAttachment = messageAttachment,
                file = file,
                uploadUrl = entity.uploadUrl,
                uploadExpiresAt = Instant.fromEpochMilliseconds(entity.expiresAt),
                publicUrl = entity.publicUrl
            )
        )
    }

    private suspend fun compressAndPrepare(
        attachmentId: String,
        rootFile: File?
    ): PreparedUploadData? {
        val pendingUpload = database.pendingAttachmentDao
            .getPendingAttachmentById(attachmentId)
            ?: run {
                logger.error("Pending attachment not found in DB for ID: $attachmentId")
                return null
            }

        val fileName = rootFile?.name ?: pendingUpload.localPath.substringAfterLast("/")
        val mimeType = getMimeTypeFromUrl(pendingUpload.uploadUrl)

        val currentLocalPath = fileStore.getFilePath(fileName)
        val originalBytes = rootFile?.bytes
            ?: fileStore.getFile(currentLocalPath)
            ?: run {
                logger.error("Failed to read bytes from local path: ${pendingUpload.localPath}")
                handleUploadFailure(attachmentId, pendingUpload.localPath)
                return null
            }

        database.messageAttachmentDao.updateAttachmentUrlAndStatus(
            attachmentId = attachmentId,
            url = currentLocalPath,
            status = AttachmentUploadStatus.UPLOADING
        )

        if (rootFile != null) {
            fileStore.saveFile(
                bytes = originalBytes,
                fileName = fileName
            )
        }

        val compressedBytes = imageCompressor.compressImage(
            File(
                name = fileName,
                bytes = originalBytes,
                mimeType = mimeType
            )
        )

        if (compressedBytes == null) {
            logger.error("Image compression returned null for file: $fileName")
            handleUploadFailure(attachmentId, pendingUpload.localPath)
            return null
        }

        return PreparedUploadData(
            pending = pendingUpload,
            compressedBytes = compressedBytes,
            mimeType = mimeType,
            fileName = fileName
        )
    }

    private suspend fun handleUploadFailure(attachmentId: String, localPath: String) {
        database.messageAttachmentDao.updateAttachmentUrlAndStatus(
            attachmentId = attachmentId,
            url = localPath,
            status = AttachmentUploadStatus.FAILED
        )
    }

    private suspend fun retryExpiredUpload(pendingAttachment: PendingAttachmentEntity): EmptyResult<DataError> {
        val fileName = pendingAttachment.localPath.substringAfterLast("/")
        val currentLocalPath = fileStore.getFilePath(fileName)
        val bytes = fileStore
            .getFile(currentLocalPath)
            ?: return Result.Failure(DataError.Local.NOT_FOUND)

        val file = File(
            name = pendingAttachment.localPath.substringAfterLast("/"),
            mimeType = getMimeTypeFromUrl(pendingAttachment.publicUrl),
            bytes = bytes
        )

        val messageWithSender = database.chatMessageDao
            .getMessageById(pendingAttachment.messageId)
            ?: return Result.Failure(DataError.Local.NOT_FOUND)

        return messageAttachmentService
            .getUploadFilesUrl(
                chatId = messageWithSender.message.chatId,
                files = listOf(file)
            )
            .onSuccess { uploadInfos ->
                val uploadInfo = uploadInfos.firstOrNull()
                    ?: return Result.Failure(DataError.Remote.UNKNOWN)

                database.pendingAttachmentDao.upsertPendingAttachment(
                    pendingAttachment.copy(
                        uploadUrl = uploadInfo.uploadUrl,
                        expiresAt = uploadInfo.expiresAt.toEpochMilliseconds(),
                        publicUrl = uploadInfo.publicUrl
                    )
                )
            }
            .onFailure {
                handleUploadFailure(pendingAttachment.attachmentId, pendingAttachment.localPath)
            }
            .map {}
    }

    private fun getMimeTypeFromUrl(url: String): String {
        val extension = url.substringBefore("?").substringAfterLast(".")
        return when (extension.lowercase()) {
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            else -> "image/webp"
        }
    }

    private data class PreparedUploadData(
        val pending: PendingAttachmentEntity,
        val compressedBytes: ByteArray,
        val mimeType: String,
        val fileName: String
    )
}
