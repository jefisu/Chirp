package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.no_messages
import chirp.feature.chat.presentation.generated.resources.no_messages_subtitle
import chirp.feature.chat.presentation.generated.resources.retry
import com.plcoding.chat.presentation.components.EmptySection
import com.plcoding.chat.presentation.model.AudioPlaybackState
import com.plcoding.chat.presentation.model.MessageUi
import com.plcoding.core.designsystem.components.buttons.ChirpButton
import com.plcoding.core.designsystem.components.buttons.ChirpButtonStyle
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import org.jetbrains.compose.resources.stringResource

@Composable
fun MessageList(
    messages: List<MessageUi>,
    paginationError: String?,
    isPaginationLoading: Boolean,
    messageWithOpenMenu: MessageUi.LocalUser?,
    audioPlaybackState: AudioPlaybackState,
    listState: LazyListState,
    onMessageLongClick: (MessageUi.LocalUser) -> Unit,
    onMessageRetryClick: (MessageUi.LocalUser) -> Unit,
    onRetryPaginationClick: () -> Unit,
    onDismissMessageMenu: () -> Unit,
    onDeleteMessageClick: (MessageUi.LocalUser) -> Unit,
    onAttachmentClick: (MessageAttachmentUi) -> Unit,
    onAttachmentLongClick: (MessageAttachmentUi) -> Unit,
    onPlayAudioClick: (MessageAttachmentUi.Audio) -> Unit,
    onPauseAudioClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    if (messages.isEmpty()) {
        Box(
            modifier = modifier
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            EmptySection(
                title = stringResource(Res.string.no_messages),
                description = stringResource(Res.string.no_messages_subtitle),
            )
        }
    } else {
        LazyColumn(
            modifier = modifier,
            state = listState,
            contentPadding = PaddingValues(16.dp),
            reverseLayout = true,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(
                items = messages,
                key = { it.id }
            ) { message ->
                MessageListItemUi(
                    messageUi = message,
                    messageWithOpenMenu = messageWithOpenMenu,
                    audioPlaybackState = audioPlaybackState,
                    onMessageLongClick = onMessageLongClick,
                    onDismissMessageMenu = onDismissMessageMenu,
                    onDeleteClick = onDeleteMessageClick,
                    onRetryClick = onMessageRetryClick,
                    onAttachmentClick = onAttachmentClick,
                    onAttachmentLongClick = onAttachmentLongClick,
                    onPlayAudioClick = onPlayAudioClick,
                    onPauseAudioClick = onPauseAudioClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .animateItem()
                )
            }

            when {
                isPaginationLoading -> {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth(),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator()
                        }
                    }
                }
                paginationError != null -> {
                    item {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            ChirpButton(
                                text = stringResource(Res.string.retry),
                                onClick = onRetryPaginationClick,
                                style = ChirpButtonStyle.SECONDARY
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = paginationError,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error,
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }
            }
        }
    }
}
