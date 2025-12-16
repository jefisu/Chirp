package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.cloud_off_icon
import chirp.feature.chat.presentation.generated.resources.send
import chirp.feature.chat.presentation.generated.resources.send_a_message
import com.plcoding.chat.domain.models.ConnectionState
import com.plcoding.chat.presentation.util.toUiText
import com.plcoding.core.designsystem.components.buttons.ChirpButton
import com.plcoding.core.designsystem.components.icon.AttachFileOutlinedIcon
import com.plcoding.core.designsystem.components.textfields.ChirpMultiLineTextField
import com.plcoding.core.designsystem.theme.ChirpTheme
import com.plcoding.core.designsystem.theme.extended
import com.plcoding.core.presentation.media.PickedImageData
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
fun MessageBox(
    messageTextFieldState: TextFieldState,
    isSendButtonEnabled: Boolean,
    connectionState: ConnectionState,
    attachedImages: List<PickedImageData>,
    onSendClick: () -> Unit,
    onAttachFilesClick: () -> Unit,
    onRemoveAttachmentClick: (PickedImageData) -> Unit,
    modifier: Modifier = Modifier,
    renderingImage: PickedImageData? = null
) {
    val isConnected = connectionState == ConnectionState.CONNECTED
    ChirpMultiLineTextField(
        state = messageTextFieldState,
        modifier = modifier
            .onPreviewKeyEvent { keyEvent ->
                val isModifierKeyPressed = keyEvent.isMetaPressed || keyEvent.isCtrlPressed
                val isSendShortcutPressed = isModifierKeyPressed
                        && keyEvent.key == Key.Enter
                        && keyEvent.type == KeyEventType.KeyDown

                if(isSendShortcutPressed) {
                    onSendClick()
                    true
                } else false
            },
        placeholder = stringResource(Res.string.send_a_message),
        keyboardOptions = KeyboardOptions(
            imeAction = ImeAction.Send
        ),
        onKeyboardAction = onSendClick,
        bottomContent = {
            Column {
                AnimatedVisibility(visible = attachedImages.isNotEmpty()) {
                    AttachmentsList(
                        images = attachedImages,
                        onRemoveClick = onRemoveAttachmentClick,
                        renderingImage = renderingImage,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp, top = 4.dp)
                    )
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Spacer(modifier = Modifier.weight(1f))
                    if (!isConnected) {
                        Icon(
                            imageVector = vectorResource(Res.drawable.cloud_off_icon),
                            contentDescription = connectionState.toUiText().asString(),
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.extended.textDisabled
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            text = connectionState.toUiText().asString(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.extended.textDisabled
                        )
                    }
                    AttachFileOutlinedIcon(
                        enabled = isConnected,
                        onClick = onAttachFilesClick
                    )
                    ChirpButton(
                        text = stringResource(Res.string.send),
                        onClick = onSendClick,
                        enabled = isConnected && isSendButtonEnabled
                    )
                }
            }
        }
    )
}

@Composable
@Preview
fun MessageBoxPreview() {
    ChirpTheme {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(300.dp),
            contentAlignment = Alignment.BottomCenter
        ) {
            MessageBox(
                messageTextFieldState = rememberTextFieldState(),
                isSendButtonEnabled = true,
                connectionState = ConnectionState.CONNECTED,
                attachedImages = emptyList(),
                onSendClick = {},
                onAttachFilesClick = {},
                onRemoveAttachmentClick = {},
                modifier = Modifier
                    .fillMaxWidth(),
            )
        }
    }
}