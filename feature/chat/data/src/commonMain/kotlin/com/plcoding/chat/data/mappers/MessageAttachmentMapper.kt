package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.MessageAttachmentDto
import com.plcoding.chat.data.dto.websocket.IncomingWebSocketDto
import com.plcoding.chat.database.entities.AttachmentUploadStatus
import com.plcoding.chat.database.entities.MessageAttachmentEntity
import com.plcoding.chat.database.entities.PendingAttachmentEntity
import com.plcoding.chat.domain.models.ChatMessage
import com.plcoding.chat.domain.models.MessageAttachment
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageAttachmentUploadStatus
import com.plcoding.chat.domain.models.PendingAttachment

fun ChatMessage.toMessageAttachmentsEntity(
    status: AttachmentUploadStatus
): List<MessageAttachmentEntity> {
    return attachments.map {
        MessageAttachmentEntity(
            id = it.id,
            url = it.url,
            messageId = id,
            type = it.type.name,
            status = status
        )
    }
}

fun MessageAttachmentEntity.toMessageAttachment(): MessageAttachment {
    return MessageAttachment(
        id = id,
        url = url,
        type = MessageAttachmentType.valueOf(type),
        status = MessageAttachmentUploadStatus.valueOf(status.name)
    )
}

fun MessageAttachmentDto.toMessageAttachment(): MessageAttachment {
    return MessageAttachment(
        id = id,
        url = url,
        type = MessageAttachmentType.valueOf(type),
        status = MessageAttachmentUploadStatus.UPLOADED
    )
}

fun MessageAttachment.toMessageAttachmentDto(): MessageAttachmentDto {
    return MessageAttachmentDto(
        id = id,
        url = url,
        type = type.name,
    )
}

fun PendingAttachment.toMessageAttachmentDto(): MessageAttachmentDto {
    return MessageAttachmentDto(
        id = messageAttachment.id,
        url = publicUrl,
        type = messageAttachment.type.name,
    )
}

fun MessageAttachment.toMessageAttachmentEntity(
    messageId: String
): MessageAttachmentEntity {
    return MessageAttachmentEntity(
        id = id,
        url = url,
        type = type.name,
        messageId = messageId,
        status = AttachmentUploadStatus.valueOf(status.name)
    )
}

fun MessageAttachmentEntity.toMessageAttachmentDto(): MessageAttachmentDto {
    return MessageAttachmentDto(
        id = id,
        url = url,
        type = type,
    )
}

fun PendingAttachment.toPendingAttachmentEntity(
    messageId: String
): PendingAttachmentEntity {
    return PendingAttachmentEntity(
        attachmentId = messageAttachment.id,
        messageId = messageId,
        uploadUrl = uploadUrl,
        expiresAt = uploadExpiresAt.toEpochMilliseconds(),
        localPath = messageAttachment.url,
        publicUrl = publicUrl
    )
}

fun IncomingWebSocketDto.NewMessageDto.toMessageAttachmentsEntities(): List<MessageAttachmentEntity> {
    return attachments.map {
        MessageAttachmentEntity(
            id = it.id,
            url = it.url,
            type = it.type,
            status = AttachmentUploadStatus.UPLOADED,
            messageId = this.id
        )
    }
}