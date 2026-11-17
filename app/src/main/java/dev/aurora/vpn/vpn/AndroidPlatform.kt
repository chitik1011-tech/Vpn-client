package dev.aurora.vpn.vpn

import android.annotation.SuppressLint
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Process
import android.system.OsConstants
import io.nekohasekai.libbox.*
import dev.aurora.vpn.data.SplitTunnelStore
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface as JavaNetworkInterface
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface

/**
 * Actual libbox Android platform integration. libbox calls openTun(), owns all packets,
 * and invokes protect(fd) for outbound sockets so they cannot recurse into this VPN.
 */
class AndroidPlatform(
    private val vpn: VpnService,
    private val keepTun: (android.os.ParcelFileDescriptor) -> Unit
) : PlatformInterface {
    private val connectivity = vpn.getSystemService(ConnectivityManager::class.java)
    private var monitor: ConnectivityManager.NetworkCallback? = null

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true
    override fun autoDetectInterfaceControl(fd: Int) {
        check(vpn.protect(fd)) { "Unable to protect outbound socket" }
    }

    override fun openTun(options: TunOptions): Int {
        check(VpnService.prepare(vpn) == null) { "VPN permission revoked" }
        val builder = vpn.Builder().setSession("Aurora VPN").setMtu(options.mtu)
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)

        val ipv4 = options.inet4Address
        var hasV4 = false
        while (ipv4.hasNext()) {
            val prefix = ipv4.next()
            builder.addAddress(prefix.address(), prefix.prefix())
            hasV4 = true
        }
        val ipv6 = options.inet6Address
        var hasV6 = false
        while (ipv6.hasNext()) {
            val prefix = ipv6.next()
            builder.addAddress(prefix.address(), prefix.prefix())
            hasV6 = true
        }
        check(hasV4 || hasV6) { "Engine requested TUN without IP addresses" }

        if (options.autoRoute) {
            val route4 = options.inet4RouteRange
            var routed4 = false
            while (route4.hasNext()) {
                val prefix = route4.next()
                builder.addRoute(prefix.address(), prefix.prefix())
                routed4 = true
            }
            if (hasV4 && !routed4) builder.addRoute("0.0.0.0", 0)
            val route6 = options.inet6RouteRange
            var routed6 = false
            while (route6.hasNext()) {
                val prefix = route6.next()
                builder.addRoute(prefix.address(), prefix.prefix())
                routed6 = true
            }
            if (hasV6 && !routed6) builder.addRoute("::", 0)

            val dns = options.dnsServerAddress
            var hasDns = false
            while (dns.hasNext()) {
                builder.addDnsServer(dns.next())
                hasDns = true
            }
            if (!hasDns) builder.addDnsServer("1.1.1.1")
        }
        // Configure exclusive per-app lists before establishment: Android forbids combining allow + deny.
        SplitTunnelStore(vpn).applyTo(builder)

        // libbox owns the FD while we retain a ParcelFileDescriptor to close on teardown.
        val pfd = builder.establish() ?: error("Android refused TUN establishment")
        keepTun(pfd)
        return pfd.fd
    }

    override fun findConnectionOwner(
        ipProtocol: Int, sourceAddress: String, sourcePort: Int,
        destinationAddress: String, destinationPort: Int
    ): ConnectionOwner {
        if (Build.VERSION.SDK_INT < 29) {
            error("Connection ownership lookup requires Android 10 or newer")
        }
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol, InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort)
        )
        check(uid != Process.INVALID_UID) { "Connection owner unavailable" }
        val owner = ConnectionOwner()
        owner.userId = uid
        val packages = vpn.packageManager.getPackagesForUid(uid) ?: emptyArray()
        owner.userName = packages.firstOrNull() ?: ""
        owner.setAndroidPackageNames(StringArray(packages.iterator()))
        return owner
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        closeDefaultInterfaceMonitor(listener)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = announce(network, listener)
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) =
                announce(network, listener)
            override fun onLost(network: Network) = announce(connectivity.activeNetwork, listener)
        }
        monitor = callback
        connectivity.registerDefaultNetworkCallback(callback)
        announce(connectivity.activeNetwork, listener)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        monitor?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        monitor = null
    }

    private fun announce(network: Network?, listener: InterfaceUpdateListener) {
        val name = network?.let { connectivity.getLinkProperties(it)?.interfaceName }
        val index = name?.let { JavaNetworkInterface.getByName(it)?.index } ?: -1
        listener.updateDefaultInterface(name ?: "", index, false, false)
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val result = mutableListOf<BoxNetworkInterface>()
        val all = JavaNetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        for (network in connectivity.allNetworks) {
            val cap = connectivity.getNetworkCapabilities(network) ?: continue
            if (cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val link = connectivity.getLinkProperties(network) ?: continue
            val javaInterface = all.firstOrNull { it.name == link.interfaceName } ?: continue
            val entry = BoxNetworkInterface()
            entry.name = javaInterface.name
            entry.index = javaInterface.index
            entry.mtu = javaInterface.mtu
            entry.addresses = StringArray(javaInterface.interfaceAddresses.map { it.prefixString() }.iterator())
            entry.dnsServer = StringArray(link.dnsServers.mapNotNull { it.hostAddress }.iterator())
            entry.gateway = StringArray(link.routes.filter { it.destination.prefixLength == 0 }
                .mapNotNull { it.gateway?.hostAddress }.iterator())
            entry.type = when {
                cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                cap.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                cap.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                else -> Libbox.InterfaceTypeOther
            }
            entry.flags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            entry.metered = !cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            result += entry
        }
        return object : NetworkInterfaceIterator {
            private val it = result.iterator()
            override fun hasNext() = it.hasNext()
            override fun next(): BoxNetworkInterface = it.next()
        }
    }

    private fun InterfaceAddress.prefixString(): String {
        val ip = if (address is Inet6Address) address.hostAddress.substringBefore('%') else address.hostAddress
        return ip + "/" + networkPrefixLength
    }

    class StringArray(private val iterator: Iterator<String>) : StringIterator {
        override fun len() = 0
        override fun hasNext() = iterator.hasNext()
        override fun next(): String = iterator.next()
    }

    override fun underNetworkExtension() = false
    override fun includeAllNetworks() = false
    override fun readWIFIState(): WIFIState? = null
    override fun clearDNSCache() {}
    override fun localDNSTransport(): LocalDNSTransport? = null
    override fun sendNotification(notification: Notification) {}
    override fun cancelNotification(identifier: String, typeID: Int) {}
    override fun startNeighborMonitor(listener: NeighborUpdateListener?) {}
    override fun closeNeighborMonitor(listener: NeighborUpdateListener?) {}
    override fun registerMyInterface(name: String?) {}
    override fun usePlatformShell() = false
    override fun checkPlatformShell() { error("Shell not supported in VPN client") }
    override fun openShellSession(
        user: PlatformUser?, command: String?, environ: StringIterator?,
        term: String?, rows: Int, cols: Int
    ): ShellSession = error("Shell not supported")
    override fun lookupUser(username: String?): PlatformUser = error("User lookup not supported")
    override fun lookupSFTPServer(): String = error("SFTP not supported")
    override fun readSystemSSHHostKey(): String = error("SSH not supported")
    override fun tailscaleHostname(): String = Build.MODEL
    override fun usePlatformBridge() = false
    override fun createBridge(options: BridgeOptions?): BridgeSession = error("Bridge requires root")
    override fun useProcFS() = false
}
