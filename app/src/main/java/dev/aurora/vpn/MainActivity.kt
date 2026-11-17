package dev.aurora.vpn

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.data.ProfileRepository
import dev.aurora.vpn.data.SplitMode
import dev.aurora.vpn.data.SplitTunnelStore
import dev.aurora.vpn.vpn.TunnelService
import dev.aurora.vpn.vpn.TunnelState
import dev.aurora.vpn.vpn.VpnStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val repository by lazy { ProfileRepository(this) }
    private val selectedPrefs by lazy { getSharedPreferences("selection", MODE_PRIVATE) }
    private val error = MutableStateFlow("")
    private var pendingConnect: String? = null
    private val permission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val id = pendingConnect
        pendingConnect = null
        if (id != null && VpnService.prepare(this) == null) launchTunnel(id)
        else error.value = "Android VPN permission is required"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        handleSharedLink(intent)
        setContent {
            val isDark = androidx.compose.foundation.isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT >= 31 && isDark -> dynamicDarkColorScheme(this)
                Build.VERSION.SDK_INT >= 31 -> dynamicLightColorScheme(this)
                isDark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = colors, typography = Typography()) {
                val profiles by repository.profiles.collectAsState()
                val status by TunnelState.state.collectAsState()
                val message by TunnelState.message.collectAsState()
                val uiError by error.collectAsState()
                var selectedId by remember { mutableStateOf(selectedPrefs.getString("selected", "")) }
                var tab by remember { mutableIntStateOf(0) }
                var inputOpen by remember { mutableStateOf(false) }
                var importText by remember { mutableStateOf("") }
                var search by remember { mutableStateOf("") }
                val selected = profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()
                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    topBar = {
                        Column(Modifier.statusBarsPadding().padding(horizontal = 24.dp, vertical = 16.dp)) {
                            Text("Aurora", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.SemiBold)
                            Text("Private connection", style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    },
                    bottomBar = {
                        NavigationBar(Modifier.navigationBarsPadding()) {
                            NavigationBarItem(tab == 0, { tab = 0 },
                                icon = { Icon(Icons.Rounded.Security, null) }, label = { Text("Home") })
                            NavigationBarItem(tab == 1, { tab = 1 },
                                icon = { Icon(Icons.Rounded.Cloud, null) }, label = { Text("Servers") })
                            NavigationBarItem(tab == 2, { tab = 2 },
                                icon = { Icon(Icons.Rounded.Settings, null) }, label = { Text("Settings") })
                        }
                    }
                ) { padding ->
                    Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 20.dp)) {
                        if (tab == 0) {
                            HomePage(
                                status, message, selected,
                                onToggle = {
                                    if (status == VpnStatus.CONNECTED || status == VpnStatus.CONNECTING) disconnect()
                                    else if (selected == null) inputOpen = true
                                    else connect(selected.id)
                                },
                                onSelectServer = { tab = 1 }
                            )
                        } else if (tab == 1) {
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Text("Servers", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
                                IconButton(onClick = { importText = ""; inputOpen = true }) {
                                    Icon(Icons.Rounded.Add, "Add server or subscription")
                                }
                                IconButton(onClick = {
                                    val clipboard = getSystemService(ClipboardManager::class.java)
                                    val text = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString()
                                    if (!text.isNullOrBlank()) importLink(text)
                                }) {
                                    Icon(Icons.Rounded.ContentPaste, "Import from clipboard")
                                }
                            }
                            OutlinedTextField(search, { search = it }, Modifier.fillMaxWidth(),
                                label = { Text("Search servers") }, singleLine = true)
                            Spacer(Modifier.height(12.dp))
                            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                items(profiles.filter { it.name.contains(search, true) }, key = { it.id }) { profile ->
                                    ElevatedCard(
                                        modifier = Modifier.fillMaxWidth().clickable {
                                            selectedId = profile.id
                                            selectedPrefs.edit().putString("selected", profile.id).apply()
                                            tab = 0
                                        },
                                        shape = RoundedCornerShape(24.dp)
                                    ) {
                                        Row(Modifier.padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
                                            Icon(Icons.Rounded.Cloud, null)
                                            Spacer(Modifier.width(16.dp))
                                            Column(Modifier.weight(1f)) {
                                                Text(profile.name, fontWeight = FontWeight.Medium,
                                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                                Text(profile.protocol + " • " +
                                                    if (profile.subscription.isEmpty()) "Manual" else "Subscription",
                                                    style = MaterialTheme.typography.bodySmall)
                                            }
                                            RadioButton(profile.id == selected?.id, onClick = {
                                                selectedId = profile.id
                                                selectedPrefs.edit().putString("selected", profile.id).apply()
                                                tab = 0
                                            })
                                        }
                                    }
                                }
                            }
                            if (profiles.isEmpty()) {
                                Text("No servers yet. Add a VLESS link or an HTTPS subscription.",
                                    modifier = Modifier.padding(16.dp),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        } else {
                            SplitTunnelingPanel()
                        }
                        if (uiError.isNotBlank()) {
                            Spacer(Modifier.height(12.dp))
                            Text(uiError, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error)
                            TextButton(onClick = { error.value = "" }) { Text("Dismiss") }
                        }
                    }
                    if (inputOpen) {
                        AlertDialog(
                            onDismissRequest = { inputOpen = false },
                            title = { Text("Import a server") },
                            text = {
                                Column {
                                    Text("Paste a VLESS link or HTTPS subscription URL.")
                                    Spacer(Modifier.height(12.dp))
                                    OutlinedTextField(importText, { importText = it }, minLines = 2,
                                        maxLines = 5, label = { Text("Link") })
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    inputOpen = false
                                    importLink(importText)
                                }) { Text("Import") }
                            },
                            dismissButton = { TextButton(onClick = { inputOpen = false }) { Text("Cancel") } }
                        )
                    }
                }
            }
        }
    }

    private fun handleSharedLink(intent: Intent?) {
        val text = when (intent?.action) {
            Intent.ACTION_VIEW -> intent.dataString
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        }
        if (!text.isNullOrBlank()) importLink(text)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleSharedLink(intent)
    }

    private fun importLink(link: String) {
        lifecycleScope.launch {
            try {
                repository.addLink(link)
                error.value = ""
            } catch (t: Exception) {
                // Never echo malformed private links, URLs or network exceptions into the UI.
                error.value = when (t) {
                    is IllegalArgumentException -> when {
                        t.message?.contains("http", ignoreCase = true) == true -> "Invalid subscription or server address"
                        t.message?.contains("vless://", ignoreCase = true) == true -> "Invalid VLESS link"
                        else -> t.message?.take(110) ?: "Invalid profile"
                    }
                    else -> "Import failed. Check the URL, format or network connection."
                }
            }
        }
    }

    private fun connect(id: String) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingConnect = id
            permission.launch(intent)
        } else launchTunnel(id)
    }

    private fun launchTunnel(id: String) {
        ContextCompat.startForegroundService(
            this, Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_START)
                .putExtra(TunnelService.EXTRA_PROFILE_ID, id)
        )
    }

    private fun disconnect() {
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
    }
}

@Composable
private fun HomePage(
    status: VpnStatus, detail: String, server: ServerProfile?,
    onToggle: () -> Unit, onSelectServer: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val active = status == VpnStatus.CONNECTED
    val scale by animateFloatAsState(if (status == VpnStatus.CONNECTING) 0.94f else 1f, label = "Power size")
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceEvenly) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                when (status) {
                    VpnStatus.CONNECTED -> "Tunnel is running"
                    VpnStatus.CONNECTING -> "Starting tunnel"
                    VpnStatus.STOPPING -> "Disconnecting"
                    VpnStatus.ERROR -> "Connection error"
                    VpnStatus.DISCONNECTED -> "Not connected"
                },
                style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Medium
            )
            Spacer(Modifier.height(10.dp))
            Text(if (active) detail else "Your connection is not protected by this VPN",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Surface(
            modifier = Modifier.size(232.dp).scale(scale).clickable {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onToggle()
            },
            shape = CircleShape,
            color = if (active) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.surfaceContainerHigh,
            border = BorderStroke(2.dp, MaterialTheme.colorScheme.outlineVariant),
            tonalElevation = 8.dp
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(Icons.Rounded.PowerSettingsNew,
                    contentDescription = if (active) "Disconnect VPN" else "Connect VPN",
                    modifier = Modifier.size(74.dp),
                    tint = if (active) MaterialTheme.colorScheme.onPrimaryContainer
                           else MaterialTheme.colorScheme.onSurface)
            }
        }
        ElevatedCard(
            Modifier.fillMaxWidth().clickable(onClick = onSelectServer),
            shape = RoundedCornerShape(28.dp)
        ) {
            Row(Modifier.padding(22.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Cloud, null, Modifier.size(30.dp))
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text("Selected server", style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(server?.name ?: "Choose a server",
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(server?.protocol ?: "No profile",
                        style = MaterialTheme.typography.bodySmall)
                }
                Text("Change", color = MaterialTheme.colorScheme.primary)
            }
        }
        Text("Actual traffic routing requires Android VPN permission and a valid server.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.labelSmall)
    }
}


@Composable
private fun SplitTunnelingPanel() {
    val context = LocalContext.current
    val store = remember(context) { SplitTunnelStore(context) }
    var mode by remember { mutableStateOf(store.mode()) }
    var selected by remember { mutableStateOf(store.selectedPackages()) }
    val apps = remember(context) { store.launchableApps(context) }

    Column(Modifier.fillMaxSize()) {
        Text("Split tunneling", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            "Choose which apps use the VPN. Changes apply on the next connection.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(20.dp))
        listOf(
            SplitMode.OFF to "All apps",
            SplitMode.INCLUDE to "Only selected",
            SplitMode.EXCLUDE to "Exclude selected"
        ).forEach { (value, label) ->
            Row(
                Modifier.fillMaxWidth().clickable {
                    mode = value
                    store.setMode(value)
                }.padding(vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(
                    selected = mode == value,
                    onClick = {
                        mode = value
                        store.setMode(value)
                    }
                )
                Spacer(Modifier.width(8.dp))
                Text(label, style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.height(12.dp))
        Text("Installed launchable apps", style = MaterialTheme.typography.titleMedium)
        if (mode == SplitMode.OFF) {
            Text("Every app uses the tunnel. Select a mode above to customize.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(selected.size.toString() + " selected",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(apps, key = { it.first }) { (packageName, appName) ->
                    val checked = packageName in selected
                    Row(
                        Modifier.fillMaxWidth().clickable {
                            selected = if (checked) selected - packageName else selected + packageName
                            store.setSelectedPackages(selected)
                        }.padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(appName, style = MaterialTheme.typography.bodyMedium)
                            Text(packageName,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Checkbox(checked, onCheckedChange = {
                            selected = if (it) selected + packageName else selected - packageName
                            store.setSelectedPackages(selected)
                        })
                    }
                }
            }
        }
    }
}
