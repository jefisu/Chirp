package com.plcoding.core.designsystem.components.icon

import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import chirp.core.designsystem.generated.resources.Res
import chirp.core.designsystem.generated.resources.attach_file_icon
import org.jetbrains.compose.resources.vectorResource

@Composable
fun AttachFileIcon(
    modifier: Modifier = Modifier,
    color: Color = LocalContentColor.current
) {
    Icon(
        imageVector = vectorResource(Res.drawable.attach_file_icon),
        contentDescription = null,
        tint = color,
        modifier = modifier
    )
}