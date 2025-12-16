package com.plcoding.core.designsystem.components.icon

import androidx.compose.foundation.layout.size
import androidx.compose.material3.IconButtonDefaults
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
    OutlinedIconButton(
        onClick = { onClick?.invoke() },
        shape = Shapes().small,
        border = IconButtonDefaults
            .outlinedIconButtonBorder(enabled = true)
            .copy(brush = SolidColor(MaterialTheme.colorScheme.extended.textSecondary)),
        enabled = enabled,
        modifier = modifier
            .size(44.dp)
    ) {
        AttachFileIcon(
            color = MaterialTheme.colorScheme.extended.textSecondary,
            modifier = Modifier.size(20.dp)
        )
    }
}