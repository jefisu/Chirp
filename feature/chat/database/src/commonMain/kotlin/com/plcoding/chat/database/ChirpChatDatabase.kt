package com.plcoding.chat.database

import androidx.room.ConstructedBy
import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.plcoding.chat.database.converters.LastMessageViewConverter
import com.plcoding.chat.database.dao.ChatDao
import com.plcoding.chat.database.dao.ChatMessageDao
import com.plcoding.chat.database.dao.ChatParticipantDao
import com.plcoding.chat.database.dao.ChatParticipantsCrossRefDao
import com.plcoding.chat.database.dao.MessageAttachmentDao
import com.plcoding.chat.database.dao.PendingAttachmentDao
import com.plcoding.chat.database.entities.ChatEntity
import com.plcoding.chat.database.entities.ChatMessageEntity
import com.plcoding.chat.database.entities.ChatParticipantCrossRef
import com.plcoding.chat.database.entities.ChatParticipantEntity
import com.plcoding.chat.database.entities.MessageAttachmentEntity
import com.plcoding.chat.database.entities.PendingAttachmentEntity
import com.plcoding.chat.database.view.LastMessageView

@Database(
    entities = [
        ChatEntity::class,
        ChatParticipantEntity::class,
        ChatMessageEntity::class,
        ChatParticipantCrossRef::class,
        MessageAttachmentEntity::class,
        PendingAttachmentEntity::class
    ],
    views = [
        LastMessageView::class
    ],
    version = 2,
)
@TypeConverters(LastMessageViewConverter::class)
@ConstructedBy(ChirpChatDatabaseConstructor::class)
abstract class ChirpChatDatabase: RoomDatabase() {
    abstract val chatDao: ChatDao
    abstract val chatParticipantDao: ChatParticipantDao
    abstract val chatMessageDao: ChatMessageDao
    abstract val chatParticipantsCrossRefDao: ChatParticipantsCrossRefDao
    abstract val messageAttachmentDao: MessageAttachmentDao
    abstract val pendingAttachmentDao: PendingAttachmentDao

    companion object {
        const val DB_NAME = "chirp.db"
    }
}
