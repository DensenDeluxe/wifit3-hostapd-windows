/*
 * hostapd 2.12 / wifit3 portable USB-radio bridge driver.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This is a hostapd driver adapter, NOT a chipset driver. The Python wifit3
 * bridge must own the USB radio and enforce focus/lease ownership.
 *
 * Message format: uint32 big-endian payload length, uint8 opcode, payload.
 * Only one authenticated controller connection is accepted by the bridge.
 * Incompatible/missing operations are rejected, never silently emulated.
 */
#include "includes.h"
#ifdef CONFIG_NATIVE_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include "common.h"
#include "driver.h"
#include "utils/eloop.h"
#include "utils/os.h"

#define W3_MAX_PACKET 16384
#define W3_MAX_FREQ 64
#define W3_PROTO 1
#define W3_CAP_TX_MGMT  1U
#define W3_CAP_TX_EAPOL 2U
#define W3_CAP_BEACON   4U
#define W3_CAP_KEY      8U
#define W3_CAP_STA      16U
#define W3_CAP_RX_MGMT  32U
#define W3_CAP_RX_EAPOL 64U
#define W3_CAP_SET_FREQ 128U
#define W3_CAP_BIP      256U
#define W3_CAP_SAE      512U
#define W3_CAP_ACCOUNTING 1024U
#define W3_CAP_GCMP     2048U
#define W3_CAP_GCMP_256 4096U
#define W3_CAP_CCMP_256 8192U
#define W3_CAP_TKIP    16384U
#define W3_MAX_STATIONS 256

/* Socket sizes are platform-specific; hostapd's eloop uses int. */
#ifdef CONFIG_NATIVE_WINDOWS
typedef SOCKET w3_socket_t;
#define W3_BAD INVALID_SOCKET
#define w3_close closesocket
#else
typedef int w3_socket_t;
#define W3_BAD (-1)
#define w3_close close
#endif

struct w3_driver {
	struct hostapd_data *hapd;
	w3_socket_t sock;
	int registered;
	u8 mac[ETH_ALEN];
	u32 cap;
	int nfreq;
	u16 freq[W3_MAX_FREQ];
	struct w3_sta_stats {
		int used;
		u8 addr[ETH_ALEN];
		unsigned long rx_packets, tx_packets;
		unsigned long long rx_bytes, tx_bytes;
		struct os_reltime last_rx;
	} stations[W3_MAX_STATIONS];
};

static void put16(u8 *p, unsigned int n) { p[0] = n >> 8; p[1] = n; }
static void put32(u8 *p, u32 n) { p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=n; }
static unsigned int get16(const u8 *p) { return ((unsigned int)p[0]<<8) | p[1]; }
static u32 get32(const u8 *p) { return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3]; }

static struct w3_sta_stats *w3_sta_find(struct w3_driver *d,
						const u8 *addr, int create)
{
	int free_slot = -1;
	int i;

	if (!(d->cap & W3_CAP_ACCOUNTING) || !addr)
		return NULL;
	for (i = 0; i < W3_MAX_STATIONS; i++) {
		if (!d->stations[i].used) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (os_memcmp(d->stations[i].addr, addr, ETH_ALEN) == 0)
			return &d->stations[i];
	}
	if (!create || free_slot < 0)
		return NULL;
	d->stations[free_slot].used = 1;
	os_memcpy(d->stations[free_slot].addr, addr, ETH_ALEN);
	os_get_reltime(&d->stations[free_slot].last_rx);
	return &d->stations[free_slot];
}

static void w3_sta_seen(struct w3_driver *d, const u8 *addr)
{
	struct w3_sta_stats *s = w3_sta_find(d, addr, 1);
	if (s)
		os_get_reltime(&s->last_rx);
}

static void w3_sta_rx(struct w3_driver *d, const u8 *addr, size_t len)
{
	struct w3_sta_stats *s = w3_sta_find(d, addr, 1);
	if (!s)
		return;
	s->rx_packets++;
	s->rx_bytes += len;
	os_get_reltime(&s->last_rx);
}

static void w3_sta_tx(struct w3_driver *d, const u8 *addr, size_t len)
{
	struct w3_sta_stats *s = w3_sta_find(d, addr, 0);
	if (!s)
		return;
	s->tx_packets++;
	s->tx_bytes += len;
}

static void w3_sta_forget(struct w3_driver *d, const u8 *addr)
{
	struct w3_sta_stats *s = w3_sta_find(d, addr, 0);
	if (s)
		os_memset(s, 0, sizeof(*s));
}

static int w3_exact_read(w3_socket_t s, u8 *p, size_t n)
{
	while (n) {
		int r = recv(s, (char *)p, (int)n, 0);
		if (r <= 0) return -1;
		p += r; n -= r;
	}
	return 0;
}

static int w3_exact_write(w3_socket_t s, const u8 *p, size_t n)
{
	while (n) {
		int r = send(s, (const char *)p, (int)n, 0);
		if (r <= 0) return -1;
		p += r; n -= r;
	}
	return 0;
}

static int w3_read(struct w3_driver *d, u8 *payload, size_t *n)
{
	u8 header[4];
	size_t length;
	if (w3_exact_read(d->sock, header, 4)) return -1;
	length = get32(header);
	if (length == 0 || length > W3_MAX_PACKET) return -1;
	if (w3_exact_read(d->sock, payload, length)) return -1;
	*n = length;
	return 0;
}

static int w3_write(struct w3_driver *d, const u8 *buf, size_t n)
{
	u8 header[4];
	if (d->sock == W3_BAD || !n || n > W3_MAX_PACKET) return -1;
	put32(header, (u32)n);
	if (w3_exact_write(d->sock, header, 4) || w3_exact_write(d->sock, buf, n))
		return -1;
	return 0;
}

/* Callback inputs are ephemeral and must be consumed during this call. */
static void w3_rx(struct w3_driver *d, const u8 *p, size_t len)
{
	union wpa_event_data e;
	if (!d->hapd || len < 1) return;
	os_memset(&e, 0, sizeof(e));
	if (p[0] == 0x30 && len >= 6) {
		size_t flen = get16(p + 4);
		if ((d->cap & W3_CAP_RX_MGMT) && flen >= 24 && flen == len - 6) {
			w3_sta_seen(d, p + 6 + 10);
			e.rx_mgmt.frame = p + 6;
			e.rx_mgmt.frame_len = flen;
			e.rx_mgmt.freq = get16(p + 1);
			e.rx_mgmt.ssi_signal = (signed char)p[3];
			e.rx_mgmt.link_id = -1;
			wpa_supplicant_event(d->hapd, EVENT_RX_MGMT, &e);
		}
	} else if (p[0] == 0x31 && len >= 9) {
		size_t flen = get16(p + 7);
		if ((d->cap & W3_CAP_RX_EAPOL) && flen >= 4 && flen == len - 9) {
			w3_sta_seen(d, p + 1);
			drv_event_eapol_rx(d->hapd, p + 1, p + 9, flen);
		}
	} else if (p[0] == 0x32 && len == 17 &&
		   (d->cap & W3_CAP_ACCOUNTING)) {
		w3_sta_rx(d, p + 1, get32(p + 13));
	}
}

/*
 * Status 0 means the frame was submitted and either link-acked or no ACK was
 * required. Status 2 means an armed link-ACK wait finished without an ACK:
 * EVENT_TX_STATUS(ack=0) must still run, because returning -1 skips the MLME
 * callback and leaves the station stuck. When the radio has no ACK tally,
 * successful submission is reported as ack=1. Association never completes if
 * that case is reported as unacked, and there is no tally that would make
 * ack=0 an observation rather than a guess.
 */
static void w3_tx_status(struct w3_driver *d, const u8 *data, size_t len,
			 int ack)
{
	union wpa_event_data e;
	u16 fc;

	if (!d->hapd || !data || len < 24)
		return;

	fc = (u16) data[0] | ((u16) data[1] << 8);
	os_memset(&e, 0, sizeof(e));
	e.tx_status.type = WLAN_FC_GET_TYPE(fc);
	e.tx_status.stype = WLAN_FC_GET_STYPE(fc);
	e.tx_status.dst = data + 4;
	e.tx_status.data = data;
	e.tx_status.data_len = len;
	e.tx_status.ack = ack;
	e.tx_status.link_id = -1;
	wpa_supplicant_event(d->hapd, EVENT_TX_STATUS, &e);
}

static void w3_disconnect(struct w3_driver *d)
{
	if (d->sock == W3_BAD)
		return;
	wpa_printf(MSG_ERROR, "wifit3: bridge disconnected");
#ifndef CONFIG_NATIVE_WINDOWS
	if (d->registered)
		eloop_unregister_read_sock((int) d->sock);
#endif
	d->registered = 0;
	w3_close(d->sock);
	d->sock = W3_BAD;
}

/* Synchronous command acknowledgment. Read until the matching reply so a
 * burst of RX events cannot leave the ACK unread and desynchronize the
 * stream. Dispatch those events only after the reply: doing it earlier can
 * re-enter the driver and consume the reply as if it belonged to the nested
 * command. seq_out requests the 0x91 get_seqnum reply. */
#define W3_RX_QUEUE_MAX 512

static int w3_rpc_seq(struct w3_driver *d, const u8 *p, size_t n, u8 *seq_out)
{
	struct w3_pending { u8 *data; size_t len; } *queue = NULL;
	u8 buf[W3_MAX_PACKET];
	size_t rlen;
	int count = 0, cap = 0, ret = -1, i;

	if (w3_write(d, p, n))
		return -1;
	for (;;) {
		if (d->sock == W3_BAD || w3_read(d, buf, &rlen)) {
			w3_disconnect(d);
			ret = -1;
			break;
		}
		if (buf[0] == 0x90 && rlen == 2) {
			if (seq_out || (buf[1] != 0 && buf[1] != 2))
				ret = -1;
			else
				ret = buf[1] == 0 ? 0 : 2;
			break;
		}
		if (buf[0] == 0x91 && rlen == 7 && seq_out) {
			os_memcpy(seq_out, buf + 1, 6);
			ret = 0;
			break;
		}
		if (buf[0] != 0x30 && buf[0] != 0x31 && buf[0] != 0x32) {
			wpa_printf(MSG_ERROR,
				   "wifit3: unexpected opcode 0x%02x while waiting for ACK",
				   buf[0]);
			w3_disconnect(d);
			ret = -1;
			break;
		}
		if (count >= W3_RX_QUEUE_MAX) {
			wpa_printf(MSG_ERROR,
				   "wifit3: RX queue exceeded while waiting for ACK");
			w3_disconnect(d);
			ret = -1;
			break;
		}
		if (count == cap) {
			int ncap = cap ? cap * 2 : 8;
			struct w3_pending *grown;

			if (ncap > W3_RX_QUEUE_MAX)
				ncap = W3_RX_QUEUE_MAX;
			grown = os_realloc(queue, (size_t) ncap * sizeof(*queue));
			if (!grown) {
				w3_disconnect(d);
				ret = -1;
				break;
			}
			queue = grown;
			cap = ncap;
		}
		queue[count].data = os_memdup(buf, rlen);
		if (!queue[count].data) {
			w3_disconnect(d);
			ret = -1;
			break;
		}
		queue[count].len = rlen;
		count++;
	}
	for (i = 0; i < count; i++) {
		w3_rx(d, queue[i].data, queue[i].len);
		os_free(queue[i].data);
	}
	os_free(queue);
	return ret;
}

static int w3_rpc(struct w3_driver *d, const u8 *p, size_t n)
{
	return w3_rpc_seq(d, p, n, NULL);
}

static void w3_eloop_rx(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct w3_driver *d = eloop_ctx;
	u8 buf[W3_MAX_PACKET];
	size_t len;
	(void)sock; (void)sock_ctx;
	if (w3_read(d, buf, &len)) {
		w3_disconnect(d);
		return;
	}
	w3_rx(d, buf, len);
}

#ifdef CONFIG_NATIVE_WINDOWS
/* The upstream Windows eloop exposes int sockets even though Win64 SOCKET
 * is pointer-sized. Poll through its timer API instead of truncating SOCKET. */
static void w3_poll_win(void *eloop_ctx, void *timeout_ctx)
{
	struct w3_driver *d = eloop_ctx;
	int drained = 0;
	(void)timeout_ctx;
	if (d->sock == W3_BAD)
		return;
	/* Drain every frame already queued. One frame per 10 ms poll falls
	 * behind a probe-response burst and fills the bridge socket. */
	for (;;) {
		fd_set rset;
		struct timeval tv;
		int ready;

		FD_ZERO(&rset);
		FD_SET(d->sock, &rset);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		ready = select(0, &rset, NULL, NULL, &tv);
		if (ready < 0) {
			w3_disconnect(d);
			return;
		}
		if (ready == 0)
			break;
		w3_eloop_rx(0, d, NULL);
		if (d->sock == W3_BAD)
			return;
		if (++drained >= 64) {
			eloop_register_timeout(0, 0, w3_poll_win, d, NULL);
			return;
		}
	}
	if (d->sock != W3_BAD)
		eloop_register_timeout(0, 10000, w3_poll_win, d, NULL);
}
#endif

static void *w3_hapd_init(struct hostapd_data *hapd,
			 struct wpa_init_params *params)
{
	struct w3_driver *d = NULL;
	struct sockaddr_in sa;
	const char *token = getenv("WIFIT3_BRIDGE_TOKEN");
	const char *portstr = getenv("WIFIT3_BRIDGE_PORT");
	const char *name = params->ifname;
	u8 packet[W3_MAX_PACKET], response[W3_MAX_PACKET];
	size_t n, tlen, namelen, rlen;
	int port = portstr ? atoi(portstr) : 6791;
#ifdef CONFIG_NATIVE_WINDOWS
	WSADATA winsock;
	if (WSAStartup(MAKEWORD(2,2), &winsock)) return NULL;
#endif
	if (!token || (tlen = strlen(token)) < 32 || tlen > 128 ||
	    !name || (namelen = strlen(name)) == 0 || namelen > 128 ||
	    port < 1024 || port > 65535) {
		wpa_printf(MSG_ERROR, "wifit3: set a >=32-byte WIFIT3_BRIDGE_TOKEN and valid port");
		goto failed;
	}
	d = os_zalloc(sizeof(*d));
	if (!d) goto failed;
	d->sock = W3_BAD;
	d->hapd = hapd;
	d->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (d->sock == W3_BAD) goto failed;
	os_memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(d->sock, (struct sockaddr *)&sa, sizeof(sa))) goto failed;
	/* Bound blocking operations. Read/write errors propagate to hostapd. */
#ifdef CONFIG_NATIVE_WINDOWS
	{
		/* Cover two radio attempts (timeout_s each) plus the retry gap.
		 * A 2 s receive timeout expires while the bridge is still
		 * waiting for USB or a link ACK and then desynchronizes the
		 * next command. */
		DWORD ms = 12000;
		setsockopt(d->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof(ms));
		setsockopt(d->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&ms, sizeof(ms));
	}
#else
	{
		struct timeval tv = { 12, 0 };
		setsockopt(d->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(d->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}
#endif
	packet[0] = 1; packet[1] = W3_PROTO; packet[2] = (u8)tlen;
	os_memcpy(packet + 3, token, tlen);
	packet[3 + tlen] = (u8)namelen;
	os_memcpy(packet + 4 + tlen, name, namelen);
	n = 4 + tlen + namelen;
	if (w3_write(d, packet, n) || w3_read(d, response, &rlen) ||
	    rlen < 13 || response[0] != 0x81 || response[1] != 0 ||
	    rlen != 13 + 2 * (size_t)response[12] ||
	    response[12] > W3_MAX_FREQ) goto failed;
	os_memcpy(d->mac, response + 2, 6);
	os_memcpy(params->own_addr, d->mac, ETH_ALEN);
	d->cap = get32(response + 8);
	d->nfreq = response[12];
	for (int i = 0; i < d->nfreq; i++) {
		unsigned int f = get16(response + 13 + 2 * i);
		/* HE/6 GHz AP operation is not represented by this v1 ABI. */
		if (!((f >= 2412 && f <= 2472 && (f - 2412) % 5 == 0) ||
		      f == 2484 || (f >= 5000 && f <= 5895 && f % 5 == 0)))
			goto failed;
		d->freq[i] = f;
	}
	if (!(d->cap & W3_CAP_TX_MGMT) || !(d->cap & W3_CAP_RX_MGMT) ||
	    !(d->cap & W3_CAP_BEACON) || !(d->cap & W3_CAP_SET_FREQ) ||
	    !d->nfreq) {
		wpa_printf(MSG_ERROR, "wifit3: radio lacks required AP/MLME capabilities");
		goto failed;
	}
#ifdef CONFIG_NATIVE_WINDOWS
	if (eloop_register_timeout(0, 10000, w3_poll_win, d, NULL) < 0)
		goto failed;
#else
	if (eloop_register_read_sock((int)d->sock, w3_eloop_rx, d, NULL) < 0)
		goto failed;
#endif
	d->registered = 1;
	wpa_printf(MSG_INFO, "wifit3: connected to authenticated USB bridge (%d frequencies)",
		   d->nfreq);
	return d;
failed:
	wpa_printf(MSG_ERROR, "wifit3: no compatible authenticated radio bridge");
	if (d) {
		if (d->sock != W3_BAD) w3_close(d->sock);
		os_free(d);
	}
#ifdef CONFIG_NATIVE_WINDOWS
	WSACleanup();
#endif
	return NULL;
}

static void w3_hapd_deinit(void *priv)
{
	struct w3_driver *d = priv;
	if (!d) return;
#ifdef CONFIG_NATIVE_WINDOWS
	if (d->registered) eloop_cancel_timeout(w3_poll_win, d, NULL);
#else
	if (d->registered) eloop_unregister_read_sock((int)d->sock);
#endif
	if (d->sock != W3_BAD) w3_close(d->sock);
	os_free(d);
#ifdef CONFIG_NATIVE_WINDOWS
	WSACleanup();
#endif
}

static int w3_get_capa(void *priv, struct wpa_driver_capa *c)
{
	struct w3_driver *d = priv;
	os_memset(c, 0, sizeof(*c));
	c->flags = WPA_DRIVER_FLAGS_AP | WPA_DRIVER_FLAGS_AP_MLME;
	c->auth = WPA_DRIVER_AUTH_OPEN;
	if ((d->cap & W3_CAP_KEY) && (d->cap & W3_CAP_TX_EAPOL) &&
	    (d->cap & W3_CAP_RX_EAPOL)) {
		c->enc = WPA_DRIVER_CAPA_ENC_CCMP;
		if (d->cap & W3_CAP_TKIP)
			c->enc |= WPA_DRIVER_CAPA_ENC_TKIP;
		if (d->cap & W3_CAP_GCMP)
			c->enc |= WPA_DRIVER_CAPA_ENC_GCMP;
		if (d->cap & W3_CAP_GCMP_256)
			c->enc |= WPA_DRIVER_CAPA_ENC_GCMP_256;
		if (d->cap & W3_CAP_CCMP_256)
			c->enc |= WPA_DRIVER_CAPA_ENC_CCMP_256;
		c->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA2;
		if (d->cap & W3_CAP_BIP)
			c->enc |= WPA_DRIVER_CAPA_ENC_BIP |
				WPA_DRIVER_CAPA_ENC_BIP_GMAC_128 |
				WPA_DRIVER_CAPA_ENC_BIP_GMAC_256 |
				WPA_DRIVER_CAPA_ENC_BIP_CMAC_256;
		if ((d->cap & W3_CAP_SAE) && (d->cap & W3_CAP_STA))
			c->key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_SAE;
	}
	return 0;
}

static struct hostapd_hw_modes *w3_hw(void *priv, u16 *num_modes,
				     u16 *flags, u8 *dfs,
				     char *alpha2, size_t alpha2_len)
{
	struct w3_driver *d = priv;
	int ct[2] = {0,0}, idx[2] = {0,0}, m, n = 0;
	struct hostapd_hw_modes *modes;
	static const int rates_g[] = {10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540};
	static const int rates_a[] = {60, 90, 120, 180, 240, 360, 480, 540};
	for (int i=0; i<d->nfreq; i++) ct[d->freq[i] < 3000 ? 0 : 1]++;
	if (ct[0]) n++;
	if (ct[1]) n++;
	if (!n) return NULL;
	modes = os_calloc(n, sizeof(*modes));
	if (!modes) return NULL;
	m = 0;
	for (int b=0;b<2;b++) {
		const int *r = b ? rates_a : rates_g;
		int nr = b ? ARRAY_SIZE(rates_a) : ARRAY_SIZE(rates_g);
		if (!ct[b]) continue;
		modes[m].mode = b ? HOSTAPD_MODE_IEEE80211A : HOSTAPD_MODE_IEEE80211G;
		modes[m].num_channels = ct[b];
		modes[m].num_rates = nr;
		modes[m].channels = os_calloc(ct[b], sizeof(struct hostapd_channel_data));
		modes[m].rates = os_malloc(nr * sizeof(int));
		if (!modes[m].channels || !modes[m].rates) goto failed;
		os_memcpy(modes[m].rates, r, nr * sizeof(int));
		m++;
	}
	for (int i=0;i<d->nfreq;i++) {
		int f = d->freq[i], b = f < 3000 ? 0 : 1;
		int mi = b && ct[0] ? 1 : 0;
		struct hostapd_channel_data *ch = &modes[mi].channels[idx[b]++];
		ch->freq = f;
		ch->allowed_bw = HOSTAPD_CHAN_WIDTH_20;
		ch->chan = f == 2484 ? 14 : f < 3000 ? (f - 2407) / 5 :
			(f - 5000) / 5;
	}
	*num_modes = n;
	if (flags) *flags = 0;
	if (dfs) *dfs = 0;
	if (alpha2 && alpha2_len) alpha2[0] = '\0';
	return modes;
failed:
	for (m=0;m<n;m++) { os_free(modes[m].channels); os_free(modes[m].rates); }
	os_free(modes);
	return NULL;
}

static int w3_set_freq(void *priv, struct hostapd_freq_params *p)
{
	struct w3_driver *d = priv;
	u8 msg[3] = { 0x10, 0, 0 };
	int found = 0;
	for (int i=0; i<d->nfreq; i++) if (d->freq[i] == p->freq) found = 1;
	if (!found || !(d->cap & W3_CAP_SET_FREQ)) return -1;
	put16(msg + 1, p->freq);
	return w3_rpc(d, msg, sizeof(msg));
}

static int w3_set_ap(void *priv, struct wpa_driver_ap_params *p)
{
	struct w3_driver *d = priv;
	u8 *msg;
	size_t n = 8 + p->head_len + p->tail_len;
	int ret;
	if (!(d->cap & W3_CAP_BEACON) || n > W3_MAX_PACKET ||
	    p->head_len > 65535 || p->tail_len > 65535) return -1;
	msg = os_malloc(n);
	if (!msg) return -1;
	msg[0] = 0x11; put16(msg + 1, p->beacon_int);
	msg[3] = (u8)p->dtim_period;
	put16(msg + 4, p->head_len);
	put16(msg + 6, p->tail_len);
	if (p->head_len) os_memcpy(msg+8,p->head,p->head_len);
	if (p->tail_len) os_memcpy(msg+8+p->head_len,p->tail,p->tail_len);
	ret = w3_rpc(d,msg,n);
	os_free(msg);
	return ret;
}

static int w3_send_mlme(void *priv, const u8 *data, size_t len,
			int noack, unsigned int freq, const u16 *offs,
			size_t offs_len, int no_encrypt, unsigned int wait,
			int link_id)
{
	struct w3_driver *d = priv;
	u8 *msg;
	int ret;
	if (!(d->cap & W3_CAP_TX_MGMT) || len > W3_MAX_PACKET-8 ||
	    offs_len || link_id >= 0 || len < 24 || wait > 65535 || freq > 65535)
		return -1;
	msg = os_malloc(len + 8);
	if (!msg) return -1;
	msg[0] = 0x12;
	put16(msg + 1, freq);
	msg[3] = (noack ? 1 : 0) | (no_encrypt ? 2 : 0);
	put16(msg + 4, wait);
	put16(msg + 6, len);
	os_memcpy(msg + 8, data, len);
	ret = w3_rpc(d,msg,len+8);
	if (ret == 0 || ret == 2) {
		w3_tx_status(d, data, len, ret == 0);
		ret = 0;
	}
	os_free(msg);
	return ret;
}

static int w3_sta_disconnect(void *priv, const u8 *own_addr,
			     const u8 *addr, u16 reason, int link_id,
			     int subtype)
{
	struct w3_driver *d = priv;
	u8 frame[26];

	/* A software station registry is required so hostapd can own the AP
	 * lifecycle; TX_MGMT is required to put the requested MLME frame on air. */
	if (!(d->cap & W3_CAP_STA) || !(d->cap & W3_CAP_TX_MGMT) ||
	    !own_addr || !addr || link_id >= 0)
		return -1;
	os_memset(frame, 0, sizeof(frame));
	frame[0] = (u8)((subtype & 0x0f) << 4);
	os_memcpy(frame + 4, addr, ETH_ALEN);
	os_memcpy(frame + 10, own_addr, ETH_ALEN);
	os_memcpy(frame + 16, own_addr, ETH_ALEN);
	WPA_PUT_LE16(frame + 24, reason);
	return w3_send_mlme(priv, frame, sizeof(frame), 0, 0, NULL, 0, 0,
			    0, link_id);
}

static int w3_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
			 u16 reason, int link_id)
{
	return w3_sta_disconnect(priv, own_addr, addr, reason, link_id, 12);
}

static int w3_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
			   u16 reason, int link_id)
{
	return w3_sta_disconnect(priv, own_addr, addr, reason, link_id, 10);
}

static int w3_eapol(void *priv, const u8 *addr, const u8 *data,
		    size_t len, int encrypt, const u8 *own_addr,
		    u32 flags, int link_id)
{
	struct w3_driver *d = priv;
	u8 *msg;
	int ret;
	(void)flags;
	if (!(d->cap & W3_CAP_TX_EAPOL) || len > W3_MAX_PACKET-16 ||
	    link_id >= 0) return -1;
	msg = os_malloc(len+16);
	if (!msg) return -1;
	msg[0] = 0x13;
	os_memcpy(msg+1, addr, 6);
	os_memcpy(msg+7, own_addr, 6);
	msg[13] = encrypt ? 1 : 0;
	put16(msg+14,len);
	os_memcpy(msg+16,data,len);
	ret = w3_rpc(d,msg,len+16);
	if (ret == 0)
		w3_sta_tx(d, addr, len);
	os_free(msg);
	return ret;
}

static int w3_read_sta_data(void *priv, struct hostap_sta_driver_data *data,
				    const u8 *addr)
{
	struct w3_driver *d = priv;
	struct w3_sta_stats *s;
	struct os_reltime now, age;

	if (!data || !(d->cap & W3_CAP_ACCOUNTING))
		return -1;
	s = w3_sta_find(d, addr, 0);
	if (!s)
		return -1;
	os_memset(data, 0, sizeof(*data));
	data->rx_packets = s->rx_packets;
	data->tx_packets = s->tx_packets;
	data->rx_bytes = s->rx_bytes;
	data->tx_bytes = s->tx_bytes;
	data->bytes_64bit = 1;
	if (os_get_reltime(&now) == 0) {
		os_reltime_sub(&now, &s->last_rx, &age);
		data->inactive_msec = (unsigned long) (age.sec * 1000 +
							 age.usec / 1000);
	}
	return 0;
}

static int w3_get_inact_sec(void *priv, const u8 *addr)
{
	struct hostap_sta_driver_data data;
	if (w3_read_sta_data(priv, &data, addr))
		return -1;
	return data.inactive_msec / 1000;
}

static int w3_sta_clear_stats(void *priv, const u8 *addr)
{
	struct w3_driver *d = priv;
	struct w3_sta_stats *s;
	if (!(d->cap & W3_CAP_ACCOUNTING))
		return -1;
	s = w3_sta_find(d, addr, 0);
	if (!s)
		return -1;
	s->rx_packets = s->tx_packets = 0;
	s->rx_bytes = s->tx_bytes = 0;
	os_get_reltime(&s->last_rx);
	return 0;
}

/* No key material is silently accepted. A radio backend must explicitly
 * implement and acknowledge installation, including replay protection. */
static int w3_set_key(void *priv, struct wpa_driver_set_key_params *p)
{
	struct w3_driver *d = priv;
	u8 *msg;
	int ret;
	size_t n = 16 + p->seq_len + p->key_len;
	if (!(d->cap & W3_CAP_KEY) || n > W3_MAX_PACKET ||
	    p->key_len > 256 || p->seq_len > 16 ||
	    (p->seq_len && !p->seq) || (p->key_len && !p->key) ||
	    p->key_idx < 0 ||
	    p->key_idx > 255 || p->alg > 255) return -1;
	msg = os_zalloc(n);
	if (!msg) return -1;
	msg[0] = 0x14;
	msg[1] = (u8)p->alg;
	msg[2] = (u8)p->key_idx;
	msg[3] = (u8)p->seq_len;
	put16(msg+4, p->key_len);
	put32(msg+6, p->key_flag);
	if (p->addr) os_memcpy(msg+10,p->addr,6);
	else os_memset(msg+10,0xff,6);
	if (p->seq_len) os_memcpy(msg+16,p->seq,p->seq_len);
	if (p->key_len) os_memcpy(msg+16+p->seq_len,p->key,p->key_len);
	ret = w3_rpc(d,msg,n);
	/* Zero the plaintext key buffer before free. */
	forced_memzero(msg,n);
	os_free(msg);
	return ret;
}

static int w3_sta_add(void *priv, struct hostapd_sta_add_params *p)
{
	struct w3_driver *d = priv;
	u8 msg[12];
	if (!(d->cap & W3_CAP_STA) || !p->addr) return -1;
	msg[0] = 0x15; os_memcpy(msg+1, p->addr, 6);
	put16(msg+7, p->aid); put16(msg+9, p->capability);
	msg[11] = p->set ? 1 : 0;
	{
		int ret = w3_rpc(d, msg, sizeof(msg));
		if (ret == 0)
			w3_sta_seen(d, p->addr);
		return ret;
	}
}

static int w3_sta_flags(void *priv, const u8 *addr,
			unsigned int total, unsigned int on, unsigned int mask)
{
	struct w3_driver *d = priv;
	u8 msg[19];
	if (!(d->cap & W3_CAP_STA)) return -1;
	msg[0] = 0x16; os_memcpy(msg+1,addr,6);
	put32(msg+7,total); put32(msg+11,on); put32(msg+15,mask);
	return w3_rpc(d,msg,sizeof(msg));
}

static int w3_get_seqnum(const char *ifname, void *priv, const u8 *addr,
			 int idx, int link_id, u8 *seq)
{
	struct w3_driver *d = priv;
	u8 msg[8];
	u8 out[6];

	(void) ifname;
	/* MLO links and a missing key buffer are outside this v1 ABI.
	 * Failure leaves the caller's buffer unchanged; M3 zeros it first,
	 * so a missing key still advertises RSC 0. */
	if (!d || !seq || link_id >= 0 || idx < 0 || idx > 255 ||
	    !(d->cap & W3_CAP_KEY))
		return -1;
	msg[0] = 0x18;
	if (addr)
		os_memcpy(msg + 1, addr, ETH_ALEN);
	else
		os_memset(msg + 1, 0xff, ETH_ALEN);
	msg[7] = (u8) idx;
	if (w3_rpc_seq(d, msg, sizeof(msg), out))
		return -1;
	os_memcpy(seq, out, sizeof(out));
	return 0;
}

static int w3_sta_remove(void *priv, const u8 *addr)
{
	struct w3_driver *d = priv;
	u8 msg[7] = { 0x17 };
	if (!(d->cap & W3_CAP_STA)) return -1;
	os_memcpy(msg+1,addr,6);
	{
		int ret = w3_rpc(d, msg, sizeof(msg));
		if (ret == 0)
			w3_sta_forget(d, addr);
		return ret;
	}
}

const struct wpa_driver_ops wpa_driver_wifit3_ops = {
	.name = "wifit3",
	.desc = "wifit3 portable USB radio IPC (Linux/macOS/Windows)",
	.hapd_init = w3_hapd_init,
	.hapd_deinit = w3_hapd_deinit,
	.get_capa = w3_get_capa,
	.get_hw_feature_data = w3_hw,
	.set_freq = w3_set_freq,
	.set_ap = w3_set_ap,
	.send_mlme = w3_send_mlme,
	.sta_deauth = w3_sta_deauth,
	.sta_disassoc = w3_sta_disassoc,
	.hapd_send_eapol = w3_eapol,
	.read_sta_data = w3_read_sta_data,
	.get_inact_sec = w3_get_inact_sec,
	.sta_clear_stats = w3_sta_clear_stats,
	.set_key = w3_set_key,
	.get_seqnum = w3_get_seqnum,
	.sta_add = w3_sta_add,
	.sta_set_flags = w3_sta_flags,
	.sta_remove = w3_sta_remove,
};
