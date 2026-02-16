package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.audio.AudioMetadata
import com.plcoding.chat.domain.models.ChatEventWithUsers
import com.plcoding.chat.domain.models.MessageAttachmentType
import com.plcoding.chat.domain.models.MessageWithSender
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.util.DateUtils
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.domain.media.File
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

private sealed interface HistoryItemWithTimestamp {
    val createdAt: Instant

    data class Message(
        val messageWithSender: MessageWithSender,
        override val createdAt: Instant
    ) : HistoryItemWithTimestamp

    data class Event(
        val eventWithUsers: ChatEventWithUsers,
        override val createdAt: Instant
    ) : HistoryItemWithTimestamp
}

fun toUiListWithEvents(
    localUserId: String,
    messages: List<MessageWithSender>,
    events: List<ChatEventWithUsers>,
    audioMetadataMap: Map<String, AudioMetadata>,
    temporaryAttachmentFiles: Map<String, File> = emptyMap(),
): List<MessageUi> {
    val messageItems = messages.map {
        HistoryItemWithTimestamp.Message(it, it.message.createdAt)
    }
    val eventItems = events.map {
        HistoryItemWithTimestamp.Event(it, it.event.createdAt)
    }

    val allItems = (messageItems + eventItems).sortedByDescending { it.createdAt }

    return allItems
        .groupBy {
            it.createdAt.toLocalDateTime(TimeZone.currentSystemDefault()).date
        }.flatMap { (date, items) ->
            items.map { item ->
                when (item) {
                    is HistoryItemWithTimestamp.Message -> item.messageWithSender.toUi(
                        localUserId = localUserId,
                        audioMetadataMap = audioMetadataMap,
                        temporaryAttachmentFiles = temporaryAttachmentFiles
                    )

                    is HistoryItemWithTimestamp.Event -> item.eventWithUsers.toUi(localUserId)
                }
            } + MessageUi.DateSeparator(
                id = date.toString(),
                date = DateUtils.formatDateSeparator(date)
            )
        }
}

fun ChatEventWithUsers.toUi(localUserId: String): MessageUi.SystemEvent {
    return MessageUi.SystemEvent(
        id = event.id,
        eventType = event.eventType,
        actorUsername = actor.username,
        targetUsername = target?.username,
        formattedTime = DateUtils.formatMessageTime(event.createdAt),
        isLocalUserActor = actor.userId == localUserId
    )
}

fun MessageWithSender.toUi(
    localUserId: String,
    audioMetadataMap: Map<String, AudioMetadata>,
    temporaryAttachmentFiles: Map<String, File> = emptyMap(),
): MessageUi {
    val isFromLocalUser = this.sender.userId == localUserId
    val attachments = message.attachments.map { attachment ->
        val contentBytes = temporaryAttachmentFiles[attachment.id]?.bytes
        when (attachment.type) {
            MessageAttachmentType.IMAGE -> MessageAttachmentUi.Image(
                id = attachment.id,
                url = attachment.url,
                status = attachment.status.toMessageAttachmentUploadStatusUi(),
                contentBytes = contentBytes,
            )

            MessageAttachmentType.AUDIO -> {
                val metadata = audioMetadataMap[attachment.id]
                MessageAttachmentUi.Audio(
                    id = attachment.id,
                    url = attachment.url,
                    status = attachment.status.toMessageAttachmentUploadStatusUi(),
                    durationMs = metadata?.durationMs,
                    amplitudes = metadata?.amplitudes ?: emptyList()
                )
            }
        }
    }

    val audioAttachment = attachments.filterIsInstance<MessageAttachmentUi.Audio>().singleOrNull()

    return if (isFromLocalUser) {
        if (audioAttachment != null && attachments.size == 1) {
            MessageUi.LocalUser.Audio(
                id = message.id,
                attachment = audioAttachment,
                deliveryStatus = message.deliveryStatus,
                formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
            )
        } else {
            MessageUi.LocalUser.Message(
                id = message.id,
                content = message.content,
                attachments = attachments,
                deliveryStatus = message.deliveryStatus,
                formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
            )
        }
    } else {
        if (audioAttachment != null && attachments.size == 1) {
            MessageUi.OtherUser.Audio(
                id = message.id,
                attachment = audioAttachment,
                formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
                sender = sender.toUi(),
            )
        } else {
            MessageUi.OtherUser.Message(
                id = message.id,
                content = message.content,
                attachments = attachments,
                formattedSentTime = DateUtils.formatMessageTime(instant = message.createdAt),
                sender = sender.toUi(),
            )
        }
    }
}
