@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.domain.media

import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreGraphics.CGRectMake
import platform.CoreGraphics.CGSizeMake
import platform.UIKit.UIGraphicsBeginImageContextWithOptions
import platform.UIKit.UIGraphicsEndImageContext
import platform.UIKit.UIGraphicsGetImageFromCurrentImageContext
import platform.UIKit.UIImage

fun UIImage.resize(width: Double, height: Double): UIImage {
    val targetSize = CGSizeMake(width, height)
    UIGraphicsBeginImageContextWithOptions(targetSize, false, 0.0)
    this.drawInRect(CGRectMake(0.0, 0.0, width, height))
    val newImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    return newImage ?: this
}
