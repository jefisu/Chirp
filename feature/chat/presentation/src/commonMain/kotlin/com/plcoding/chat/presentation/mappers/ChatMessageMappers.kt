package com.plcoding.chat.presentation.mappers

import com.plcoding.chat.domain.models.ChatEventWithUsers
import com.plcoding.chat.domain.models.MessageWithSender
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.chat.presentation.util.DateUtils
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

fun List<MessageWithSender>.toUiList(
    localUserId: String,
    temporaryAttachmentFiles: Map<String, File> = emptyMap()
): List<MessageUi> {
    return toUiListWithEvents(
        localUserId = localUserId,
        messages = this,
        events = emptyList(),
        temporaryAttachmentFiles = temporaryAttachmentFiles
    )
}

fun toUiListWithEvents(
    localUserId: String,
    messages: List<MessageWithSender>,
    events: List<ChatEventWithUsers>,
    temporaryAttachmentFiles: Map<String, File> = emptyMap()
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
        }
        .flatMap { (date, items) ->
            items.map { item ->
                when (item) {
                    is HistoryItemWithTimestamp.Message -> item.messageWithSender.toUi(
                        localUserId = localUserId,
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
