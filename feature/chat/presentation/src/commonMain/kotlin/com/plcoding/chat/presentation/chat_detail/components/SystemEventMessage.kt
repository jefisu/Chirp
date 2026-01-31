package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.participant_added_event
import chirp.feature.chat.presentation.generated.resources.participant_removed_event
import chirp.feature.chat.presentation.generated.resources.you_added_participant_event
import chirp.feature.chat.presentation.generated.resources.you_removed_participant_event
import com.plcoding.chat.domain.models.ChatEventType
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.theme.ChirpTheme
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun SystemEventMessage(
    event: MessageUi.SystemEvent,
    modifier: Modifier = Modifier
) {
    val text = when {
        event.isLocalUserActor && event.eventType == ChatEventType.PARTICIPANT_REMOVED -> {
            stringResource(
                Res.string.you_removed_participant_event,
                event.targetUsername ?: ""
            )
        }
        event.isLocalUserActor && event.eventType == ChatEventType.PARTICIPANT_ADDED -> {
            stringResource(
                Res.string.you_added_participant_event,
                event.targetUsername ?: ""
            )
        }
        event.eventType == ChatEventType.PARTICIPANT_REMOVED -> {
            stringResource(
                Res.string.participant_removed_event,
                event.actorUsername,
                event.targetUsername ?: ""
            )
        }
        event.eventType == ChatEventType.PARTICIPANT_ADDED -> {
            stringResource(
                Res.string.participant_added_event,
                event.actorUsername,
                event.targetUsername ?: ""
            )
        }
        else -> ""
    }

    Box(
        modifier = modifier
            .fillMaxWidth(),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .background(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(12.dp)
                )
                .padding(horizontal = 12.dp, vertical = 6.dp)
        )
    }
}

@Preview
@Composable
private fun SystemEventMessagePreview() {
    ChirpTheme {
        SystemEventMessage(
            event = MessageUi.SystemEvent(
                id = "1",
                eventType = ChatEventType.PARTICIPANT_REMOVED,
                actorUsername = "John",
                targetUsername = "Alice",
                formattedTime = com.plcoding.core.presentation.util.UiText.DynamicString("10:30 AM"),
                isLocalUserActor = false
            )
        )
    }
}
