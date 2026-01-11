@file:OptIn(ExperimentalSharedTransitionApi::class)

package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.ExperimentalSharedTransitionApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.paint
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.save
import coil3.compose.rememberAsyncImagePainter
import com.plcoding.core.designsystem.components.chat.MessageAttachmentUi
import com.plcoding.core.designsystem.components.dialogs.ChirpAdaptiveDialog
import com.plcoding.core.designsystem.theme.ChirpBase0
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.presentation.util.calculateImageSizing
import com.plcoding.core.presentation.util.currentDeviceConfiguration
import org.jetbrains.compose.resources.stringResource

@Composable
fun AttachmentContextMenu(
    attachment: MessageAttachmentUi?,
    onDismiss: () -> Unit,
    onSaveClick: () -> Unit,
) {
    val deviceConfiguration = currentDeviceConfiguration()
    val painter = rememberAsyncImagePainter(attachment?.url)
    val sizing = calculateImageSizing(
        intrinsicSize = painter.intrinsicSize,
        deviceConfiguration = deviceConfiguration,
        applyPadding = false
    )

    ChirpAdaptiveDialog(
        isVisible = attachment != null,
        onDismiss = onDismiss
    ) {
        Column(
            modifier = Modifier
                .pointerInput(Unit) {
                    detectTapGestures { onDismiss() }
                }
                .padding(24.dp)
        ) {
            Box(
                modifier = sizing.modifier
                    .clip(MaterialTheme.shapes.medium)
                    .border(
                        width = 4.dp,
                        color = ChirpBase0,
                        shape = MaterialTheme.shapes.medium
                    )
                    .paint(
                        painter = painter,
                        contentScale = sizing.contentScale
                    )
            )
            Spacer(Modifier.height(16.dp))
            Column(
                modifier = Modifier
                    .align(Alignment.End)
                    .clip(MaterialTheme.shapes.large)
                    .background(MaterialTheme.colorScheme.surface)
            ) {
                ContextMenuItem(
                    title = stringResource(Res.string.save),
                    icon = Icons.Default.Save,
                    onClick = onSaveClick
                )
            }
        }
    }
}

@Composable
private fun ContextMenuItem(
    title: String,
    icon: ImageVector,
    onClick: () -> Unit,
    contentColor: Color = MaterialTheme.colorScheme.extended.textPrimary
) {
    Row(
        modifier = Modifier
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
            color = contentColor,
            fontWeight = FontWeight.Medium
        )
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = contentColor,
            modifier = Modifier.size(24.dp)
        )
    }
}
