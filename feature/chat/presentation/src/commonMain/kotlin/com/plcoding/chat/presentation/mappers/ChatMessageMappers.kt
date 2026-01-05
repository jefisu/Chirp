package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.models.MessageWithSender
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.util.DateUtils
import com.plcoding.core.domain.media.File
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

fun List<MessageWithSender>.toUiList(
    localUserId: String,
    temporaryAttachmentFiles: Map<String, File> = emptyMap()
): List<MessageUi> {
    return this
        .sortedByDescending { it.message.createdAt }
        .groupBy {
            it.message.createdAt.toLocalDateTime(TimeZone.currentSystemDefault()).date
        }
        .flatMap { (date, messages) ->
            messages.map {
                it.toUi(
                    localUserId = localUserId,
                    temporaryAttachmentFiles = temporaryAttachmentFiles
                )
            } + MessageUi.DateSeparator(
                id = date.toString(),
                date = DateUtils.formatDateSeparator(date)
            )
        }
}

fun MessageWithSender.toUi(
    localUserId: String,
    temporaryAttachmentFiles: Map<String, File> = emptyMap()
): MessageUi {
    val isFromLocalUser = this.sender.userId == localUserId
    return if (isFromLocalUser) {
        MessageUi.LocalUserMessage(
            id = message.id,
            content = message.content,
            attachments = message.attachments.map {
                it.toMessageAttachmentUi().copy(
                    contentBytes = temporaryAttachmentFiles[it.id]?.bytes
                )
            },
            deliveryStatus = message.deliveryStatus,
            formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
        )
    } else {
        MessageUi.OtherUserMessage(
            id = message.id,
            content = message.content,
            attachments = message.attachments.map { it.toMessageAttachmentUi() },
            formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
            sender = sender.toUi(),
        )
    }
}
