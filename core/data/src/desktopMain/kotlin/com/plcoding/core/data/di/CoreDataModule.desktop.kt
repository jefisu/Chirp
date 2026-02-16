package com.plcoding.core.data.di

import com.plcoding.core.data.audio.NativeAudioFileCache
import com.plcoding.core.data.audio.NativeAudioMetadataExtractor
import com.plcoding.core.data.audio.NativeAudioPlayer
import com.plcoding.core.data.audio.NativeAudioRecorder
import com.plcoding.core.data.auth.createDataStore
import com.plcoding.core.data.media.JvmFileStore
import com.plcoding.core.data.media.NativeFileStore
import com.plcoding.core.data.preferences.DataStoreThemePreferences
import com.plcoding.core.data.security.NativeSecureStorage
import com.plcoding.core.domain.audio.AudioFileCache
import com.plcoding.core.domain.audio.AudioMetadataExtractor
import com.plcoding.core.domain.audio.AudioPlayer
import com.plcoding.core.domain.audio.AudioRecorder
import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.preferences.ThemePreferences
import com.plcoding.core.domain.security.SecureStorage
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.bind
import org.koin.dsl.module

actual val platformCoreDataModule = module {
    single { createDataStore() }
    single<HttpClientEngine> { OkHttp.create() }
    singleOf(::DataStoreThemePreferences) bind ThemePreferences::class
    singleOf(::NativeSecureStorage).bind<SecureStorage>()
    singleOf(::JvmFileStore)
    singleOf(::NativeFileStore).bind<FileStore>()
    singleOf(::NativeAudioRecorder).bind<AudioRecorder>()
    singleOf(::NativeAudioPlayer).bind<AudioPlayer>()
    singleOf(::NativeAudioMetadataExtractor).bind<AudioMetadataExtractor>()
    singleOf(::NativeAudioFileCache).bind<AudioFileCache>()
}
