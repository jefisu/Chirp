package com.plcoding.core.data.di

import com.plcoding.core.data.media.JvmFileStore
import com.plcoding.core.data.media.NativeFileStore
import com.plcoding.core.data.security.NativeSecureStorage
import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.security.SecureStorage
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.bind
import org.koin.dsl.module

actual val platformCoreDataModule = module {
    single<HttpClientEngine> { OkHttp.create() }
    singleOf(::NativeSecureStorage).bind<SecureStorage>()
    singleOf(::JvmFileStore)
    singleOf(::NativeFileStore).bind<FileStore>()
}
