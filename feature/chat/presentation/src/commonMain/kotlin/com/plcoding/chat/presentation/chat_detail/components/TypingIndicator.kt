package com.plcoding.chat.presentation.chat_detail.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.plcoding.core.designsystem.theme.extended

@Composable
fun TypingIndicator(
    typingText: String?,
    modifier: Modifier = Modifier
) {
    AnimatedVisibility(
        visible = typingText != null,
        enter = fadeIn() + expandVertically(),
        exit = fadeOut() + shrinkVertically(),
        modifier = modifier
    ) {
        typingText?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.extended.textPlaceholder,
            )
        }
    }
}
