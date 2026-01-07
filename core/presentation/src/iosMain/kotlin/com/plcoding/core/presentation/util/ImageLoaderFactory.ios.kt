package com.plcoding.core.presentation.util

import androidx.compose.runtime.Composable

@Composable
actual fun ImageLoaderFactory() {
    // On iOS, we avoid a global ImageLoader singleton to prevent Main Thread freezes
    // caused by synchronous filesystem initialization (DiskCache) during startup.
}