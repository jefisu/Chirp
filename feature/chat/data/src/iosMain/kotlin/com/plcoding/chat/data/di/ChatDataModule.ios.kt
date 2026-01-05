package com.plcoding.chat.data.di

import com.plcoding.chat.data.lifecycle.AppLifecycleObserver
import com.plcoding.chat.data.message.IosBackgroundUploadManager
import com.plcoding.chat.data.message.NativeMessageAttachmentScheduler
import com.plcoding.chat.data.message.UploaderMessageAttachmentService
import com.plcoding.chat.data.network.ConnectionErrorHandler
import com.plcoding.chat.data.network.ConnectivityObserver
import com.plcoding.chat.data.notification.FirebasePushNotificationService
import com.plcoding.chat.database.DatabaseFactory
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.notification.PushNotificationService
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.bind
import org.koin.dsl.module

actual val platformChatDataModule = module {
    single { DatabaseFactory() }
    singleOf(::AppLifecycleObserver)
    singleOf(::ConnectivityObserver)
    singleOf(::ConnectionErrorHandler)
    singleOf(::FirebasePushNotificationService) bind PushNotificationService::class
    singleOf(::NativeMessageAttachmentScheduler).bind<MessageAttachmentScheduler>()
    singleOf(::IosBackgroundUploadManager)
    singleOf(::UploaderMessageAttachmentService)
}
