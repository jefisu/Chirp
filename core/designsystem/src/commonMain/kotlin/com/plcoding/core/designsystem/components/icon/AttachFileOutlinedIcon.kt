package com.plcoding.core.designsystem.components.icon

import androidx.compose.foundation.layout.size
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.Shapes
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.unit.dp
import com.plcoding.core.designsystem.theme.extended

@Composable
fun AttachFileOutlinedIcon(
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
) {
    val borderColor = MaterialTheme.colorScheme.extended.disabledOutline

    OutlinedIconButton(
        onClick = { onClick?.invoke() },
        shape = Shapes().small,
        border = IconButtonDefaults
            .outlinedIconButtonBorder(enabled = enabled)
            .copy(
                brush = SolidColor(borderColor)
            ),
        colors = IconButtonDefaults.iconButtonColors(
            contentColor = MaterialTheme.colorScheme.extended.textSecondary,
            disabledContentColor = MaterialTheme.colorScheme.extended.textDisabled,
        ),
        enabled = enabled,
        modifier = modifier
            .size(44.dp)
    ) {
        AttachFileIcon(
            color = LocalContentColor.current,
            modifier = Modifier.size(20.dp)
        )
    }
}