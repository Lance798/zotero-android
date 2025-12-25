package org.zotero.android.webdav.network

import android.content.Context
import android.net.wifi.WifiManager
import android.os.SystemClock
import okhttp3.Dns
import timber.log.Timber
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Locale

private const val MDNS_ADDRESS = "224.0.0.251"
private const val MDNS_PORT = 5353

/**
 * Minimal mDNS resolver that falls back to the default system DNS for non-mDNS
 * queries and only handles A records.
 */
class MdnsDns(
    private val context: Context,
    private val fallback: Dns = Dns.SYSTEM,
    private val timeoutMs: Int = 2_000,
    private val cacheTtlMs: Long = 120_000
) : Dns {

    private data class CacheEntry(val expiresAt: Long, val addresses: List<InetAddress>)
    private val cache = mutableMapOf<String, CacheEntry>()

    override fun lookup(hostname: String): List<InetAddress> {
        if (hostname.isBlank()) {
            throw UnknownHostException("Hostname is empty")
        }

        cache[hostname.lowercase(Locale.US)]?.let { entry ->
            if (entry.expiresAt > SystemClock.elapsedRealtime()) {
                return entry.addresses
            }
        }

        return try {
            fallback.lookup(hostname)
        } catch (original: UnknownHostException) {
            if (!hostname.isMdnsHost()) {
                throw original
            }
            val mdnsAddresses = resolveViaMdns(hostname)
            if (mdnsAddresses.isNotEmpty()) {
                cache[hostname.lowercase(Locale.US)] =
                    CacheEntry(SystemClock.elapsedRealtime() + cacheTtlMs, mdnsAddresses)
                mdnsAddresses
            } else {
                throw original
            }
        }
    }

    private fun resolveViaMdns(hostname: String): List<InetAddress> {
        val multicastAddress = InetAddress.getByName(MDNS_ADDRESS)
        val addresses = mutableSetOf<InetAddress>()
        var multicastLock: WifiManager.MulticastLock? = null
        var socket: DatagramSocket? = null
        try {
            multicastLock = (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
                ?.createMulticastLock("zotero-mdns")
            multicastLock?.setReferenceCounted(true)
            multicastLock?.acquire()

            socket = try {
                MulticastSocket(MDNS_PORT).apply {
                    reuseAddress = true
                    joinGroup(multicastAddress)
                    soTimeout = timeoutMs
                    timeToLive = 255
                }
            } catch (e: SecurityException) {
                Timber.w(e, "mDNS multicast socket not allowed, falling back to unicast socket")
                DatagramSocket().apply {
                    soTimeout = timeoutMs
                }
            } catch (e: Exception) {
                Timber.w(e, "mDNS multicast socket not available, falling back to unicast socket")
                DatagramSocket().apply {
                    soTimeout = timeoutMs
                }
            }

            val query = buildMdnsQuery(hostname)
            val packet = DatagramPacket(query, query.size, multicastAddress, MDNS_PORT)
            socket.send(packet)

            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            while (SystemClock.elapsedRealtime() < deadline) {
                val buffer = ByteArray(1500)
                val response = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(response)
                } catch (_: SocketTimeoutException) {
                    break
                }
                addresses.addAll(parseARecords(hostname, response.data, response.length))
                if (addresses.isNotEmpty()) {
                    break
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "mDNS lookup failed for %s", hostname)
        } finally {
            try {
                (socket as? MulticastSocket)?.leaveGroup(multicastAddress)
            } catch (_: Exception) {
                //no-op
            }
            socket?.close()
            try {
                multicastLock?.release()
            } catch (_: Exception) {
                //no-op
            }
        }
        return addresses.toList()
    }

    private fun String.isMdnsHost(): Boolean =
        lowercase(Locale.US).let { it.endsWith(".local") || it.endsWith(".home.arpa") }

    private fun buildMdnsQuery(hostname: String): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeShort(0) // Transaction ID
            stream.writeShort(0) // Flags
            stream.writeShort(1) // Questions
            stream.writeShort(0) // Answer RRs
            stream.writeShort(0) // Authority RRs
            stream.writeShort(0) // Additional RRs
            writeQName(stream, hostname)
            stream.writeShort(1) // Type A
            stream.writeShort(0x8001) // Class IN with unicast response flag
        }
        return output.toByteArray()
    }

    private fun writeQName(stream: DataOutputStream, hostname: String) {
        hostname.trimEnd('.').split(".").forEach { label ->
            val bytes = label.toByteArray(Charsets.UTF_8)
            stream.writeByte(bytes.size)
            stream.write(bytes)
        }
        stream.writeByte(0) // End of name
    }

    private fun parseARecords(
        hostname: String,
        data: ByteArray,
        length: Int
    ): List<InetAddress> {
        if (length < 12) {
            return emptyList()
        }
        val expectedName = hostname.trimEnd('.').lowercase(Locale.US)
        var offset = 12
        val questionCount = readUInt16(data, 4)
        val answerCount = readUInt16(data, 6)

        repeat(questionCount) {
            val nameResult = readName(data, offset, length) ?: return emptyList()
            offset = nameResult.second + 4 // skip type and class
        }

        val addresses = mutableListOf<InetAddress>()
        repeat(answerCount) {
            val nameResult = readName(data, offset, length) ?: return@repeat
            val recordName = nameResult.first
            offset = nameResult.second
            if (offset + 10 > length) {
                return@repeat
            }
            val type = readUInt16(data, offset)
            val clazz = readUInt16(data, offset + 2)
            offset += 8 // skip type, class and TTL
            val rdLength = readUInt16(data, offset)
            offset += 2
            if (offset + rdLength > length) {
                offset = length
                return@repeat
            }
            if (type == 1 && clazz and 0x7FFF == 1 && rdLength == 4 &&
                recordName.equals(expectedName, ignoreCase = true)
            ) {
                try {
                    addresses.add(InetAddress.getByAddress(data.copyOfRange(offset, offset + rdLength)))
                } catch (_: Exception) {
                    //no-op
                }
            }
            offset += rdLength
        }
        return addresses
    }

    private fun readName(
        data: ByteArray,
        start: Int,
        length: Int
    ): Pair<String, Int>? {
        var offset = start
        val labels = mutableListOf<String>()
        var jumped = false
        var jumpOffset = -1

        while (offset < length) {
            val len = data[offset].toInt() and 0xFF
            when {
                len == 0 -> {
                    offset++
                    val endOffset = if (jumped) jumpOffset else offset
                    return labels.joinToString(".") to endOffset
                }
                len and 0xC0 == 0xC0 -> {
                    if (offset + 1 >= length) {
                        return null
                    }
                    val pointer =
                        ((len and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                    if (!jumped) {
                        jumpOffset = offset + 2
                        jumped = true
                    }
                    offset = pointer
                }
                else -> {
                    if (offset + 1 + len > length) {
                        return null
                    }
                    labels.add(String(data, offset + 1, len, Charsets.UTF_8))
                    offset += len + 1
                }
            }
        }
        return null
    }

    private fun readUInt16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
}
