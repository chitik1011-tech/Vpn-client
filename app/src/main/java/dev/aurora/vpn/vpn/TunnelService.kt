package dev.aurora.vpn.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import dev.aurora.vpn.MainActivity
import dev.aurora.vpn.R
import dev.aurora.vpn.core.SingBoxConfig
import dev.aurora.vpn.data.SecretStore
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class VpnStatus { DISCONNECTED, CONNECTING, CONNECTED, STOPPING, ERROR }
object TunnelState {
    private val mutable = MutableStateFlow(VpnStatus.DISCONNECTED)
    val state = mutable.asStateFlow()
    var message = MutableStateFlow("")
    internal fun set(status: VpnStatus, detail: String = "") {
        message.value = detail
        mutable.value = status
    }
}

class TunnelService : VpnService(), CommandServerHandler {
    companion object {
        const val ACTION_START = "dev.aurora.vpn.action.START"
        const val ACTION_STOP = "dev.aurora.vpn.action.STOP"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 42
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var server: CommandServer? = null
    private var tun: ParcelFileDescriptor? = null
    private var startJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.vpn_channel), NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                if (startJob?.isActive == true || server != null) return START_NOT_STICKY
                startForeground(NOTIFICATION, notification("Starting VPN"))
                val id = intent.getStringExtra(EXTRA_PROFILE_ID)
                startJob = scope.launch { startTunnel(id) }
            }
            else -> {
                // Android Always-on may start this service without an explicit profile.
                if (server == null) {
                    startForeground(NOTIFICATION, notification("VPN requires a selected server"))
                    TunnelState.set(VpnStatus.ERROR, "Select a server in Aurora VPN")
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun startTunnel(profileId: String?) {
        TunnelState.set(VpnStatus.CONNECTING)
        try {
            check(VpnService.prepare(this) == null) { "VPN permission not granted" }
            val selected = SecretStore(this).read().firstOrNull { it.id == profileId }
                ?: error("Selected server not available")
            val config = SingBoxConfig.build(selected)
            val options = SetupOptions().apply {
                basePath = filesDir.absolutePath
                workingPath = filesDir.absolutePath
                tempPath = cacheDir.absolutePath
                debug = BuildConfig.DEBUG
            }
            Libbox.setup(options)
            val platform = AndroidPlatform(this) { newTun ->
                tun?.close()
                tun = newTun
            }
            val command = CommandServer(this, platform)
            server = command
            command.start()
            command.startOrReloadService(config, OverrideOptions())
            check(tun != null) { "sing-box started without opening Android TUN" }
            TunnelState.set(VpnStatus.CONNECTED, selected.name)
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION, notification("Tunnel running: " + selected.name))
        } catch (e: Exception) {
            // Do not log config, token, UUID, subscription URL or native stack containing secrets.
            TunnelState.set(VpnStatus.ERROR, e.javaClass.simpleName + ": VPN startup failed")
            release()
            stopSelf()
        }
    }

    private fun notification(text: String): android.app.Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle("Aurora VPN")
            .setContentText(text)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .build()
    }

    private fun stopTunnel() {
        TunnelState.set(VpnStatus.STOPPING)
        startJob?.cancel()
        release()
        TunnelState.set(VpnStatus.DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @Synchronized
    private fun release() {
        val running = server
        server = null
        runCatching { running?.closeService() }
        runCatching { running?.close() }
        runCatching { tun?.close() }
        tun = null
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        startJob?.cancel()
        release()
        scope.cancel()
        if (TunnelState.state.value != VpnStatus.ERROR)
            TunnelState.set(VpnStatus.DISCONNECTED)
        super.onDestroy()
    }

    // CommandServerHandler callbacks come from libbox.
    override fun serviceStop() { stopTunnel() }
    override fun serviceReload() {}
    override fun getSystemProxyStatus(): SystemProxyStatus? = null
    override fun setSystemProxyEnabled(isEnabled: Boolean) {}
    override fun triggerNativeCrash() {}
    override fun writeDebugMessage(message: String?) {}
    override fun connectSSHAgent(): Int = -1
}
