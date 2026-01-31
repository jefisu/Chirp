package com.plcoding.chat.presentation.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.admin
import chirp.feature.chat.presentation.generated.resources.remove_member
import com.plcoding.core.designsystem.components.avatar.ChatParticipantUi
import com.plcoding.core.designsystem.components.avatar.ChirpAvatarPhoto
import com.plcoding.core.designsystem.components.brand.ChirpHorizontalDivider
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.designsystem.theme.titleXSmall
import com.plcoding.core.presentation.util.DeviceConfiguration
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.resources.stringResource

@Composable
fun ColumnScope.ChatParticipantsSelectionSection(
    existingParticipants: List<ChatParticipantUi>,
    selectedParticipants: List<ChatParticipantUi>,
    modifier: Modifier = Modifier,
    searchResult: ChatParticipantUi? = null,
    isCurrentUserAdmin: Boolean = false,
    creatorId: String? = null,
    localUserId: String? = null,
    onRemoveMemberClick: ((String) -> Unit)? = null
) {
    val deviceConfiguration = currentDeviceConfiguration()
    val rootHeightModifier = when (deviceConfiguration) {
        DeviceConfiguration.TABLET_PORTRAIT,
        DeviceConfiguration.TABLET_LANDSCAPE,
        DeviceConfiguration.DESKTOP -> {
            Modifier
                .animateContentSize()
                .heightIn(min = 200.dp, max = 300.dp)
        }

        else -> Modifier
            .weight(1f)
    }

    val sortedParticipants = existingParticipants.sortedWith(
        compareByDescending<ChatParticipantUi> { it.id == localUserId }
            .thenBy { it.username }
    )

    Box(
        modifier = rootHeightModifier
            .then(modifier)
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Box(Modifier)
            }

            items(
                items = sortedParticipants,
                key = { "existing_${it.id}" }
            ) { participant ->
                val isAdmin = participant.id == creatorId
                val canRemove = isCurrentUserAdmin && !isAdmin && onRemoveMemberClick != null
                ChatParticipantListItem(
                    participantUi = participant,
                    isAdmin = isAdmin,
                    showRemoveButton = canRemove,
                    onRemoveClick = if (canRemove) {
                        { onRemoveMemberClick.invoke(participant.id) }
                    } else null,
                    modifier = Modifier
                        .fillMaxWidth()
                )
            }

            if (existingParticipants.isNotEmpty()) {
                item {
                    ChirpHorizontalDivider()
                }
            }

            searchResult?.let {
                item {
                    ChatParticipantListItem(
                        participantUi = searchResult,
                        modifier = Modifier
                            .fillMaxWidth()
                    )
                }
            }

            if (selectedParticipants.isNotEmpty() && searchResult == null) {
                items(
                    items = selectedParticipants,
                    key = { it.id }
                ) { participant ->
                    ChatParticipantListItem(
                        participantUi = participant,
                        modifier = Modifier
                            .fillMaxWidth()
                    )
                }
            }
        }
    }
}

@Composable
fun ChatParticipantListItem(
    participantUi: ChatParticipantUi,
    modifier: Modifier = Modifier,
    isAdmin: Boolean = false,
    showRemoveButton: Boolean = false,
    onRemoveClick: (() -> Unit)? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(
                start = 16.dp,
                end = if (showRemoveButton) 4.dp else 16.dp,
            ),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ChirpAvatarPhoto(
            displayText = participantUi.initials,
            imageUrl = participantUi.imageUrl
        )
        Text(
            text = participantUi.username,
            style = MaterialTheme.typography.titleXSmall,
            color = MaterialTheme.colorScheme.extended.textPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        if (isAdmin) {
            Text(
                text = stringResource(Res.string.admin),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
        }
        if (showRemoveButton && onRemoveClick != null) {
            IconButton(onClick = onRemoveClick) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = stringResource(Res.string.remove_member),
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}