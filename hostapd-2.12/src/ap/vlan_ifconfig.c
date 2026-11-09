/*
 * hostapd / VLAN ifconfig helpers
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#ifdef CONFIG_NATIVE_WINDOWS

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include "utils/common.h"
#include "vlan_util.h"

static int windows_adapter_exists(const char *ifname)
{
	IP_ADAPTER_ADDRESSES *adapters = NULL, *adapter;
	ULONG len = 15000;
	DWORD ret;
	int found = 0;

	if (!ifname || !ifname[0])
		return 0;

	adapters = os_malloc(len);
	if (!adapters)
		return 0;

	ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &len);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		IP_ADAPTER_ADDRESSES *tmp = os_realloc(adapters, len);
		if (!tmp) {
			os_free(adapters);
			return 0;
		}
		adapters = tmp;
		ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &len);
	}

	if (ret != NO_ERROR)
		goto out;

	for (adapter = adapters; adapter; adapter = adapter->Next) {
		char friendly[256];
		int n;

		if (os_strcmp(adapter->AdapterName, ifname) == 0) {
			found = 1;
			break;
		}
		if (!adapter->FriendlyName)
			continue;
		n = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
					friendly, sizeof(friendly), NULL, NULL);
		if (n > 0 && os_strcmp(friendly, ifname) == 0) {
			found = 1;
			break;
		}
	}

out:
	os_free(adapters);
	return found;
}


int ifconfig_helper(const char *if_name, int up)
{
	if (!windows_adapter_exists(if_name)) {
		wpa_printf(MSG_ERROR,
			   "VLAN: Windows adapter '%s' does not exist",
			   if_name ? if_name : "(null)");
		return -1;
	}

	/* Windows does not expose the Linux SIOCSIFFLAGS operation used by
	 * hostapd here. Adapter power/operational state is owned by the OS; the
	 * existing adapter is already usable for the wifit3 data path. */
	wpa_printf(MSG_DEBUG,
		   "VLAN: Windows adapter '%s' assumed %s (state change is OS-managed)",
		   if_name, up ? "up" : "down");
	return 0;
}


int ifconfig_up(const char *if_name)
{
	wpa_printf(MSG_DEBUG, "VLAN: Set interface %s up", if_name);
	return ifconfig_helper(if_name, 1);
}


int iface_exists(const char *ifname)
{
	return windows_adapter_exists(ifname);
}

#else /* CONFIG_NATIVE_WINDOWS */

#include <net/if.h>
#include <sys/ioctl.h>

#include "utils/common.h"
#include "vlan_util.h"


int ifconfig_helper(const char *if_name, int up)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: ioctl(SIOCGIFFLAGS) failed "
			   "for interface %s: %s",
			   __func__, if_name, strerror(errno));
		close(fd);
		return -1;
	}

	if (up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: ioctl(SIOCSIFFLAGS) failed "
			   "for interface %s (up=%d): %s",
			   __func__, if_name, up, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}


int ifconfig_up(const char *if_name)
{
	wpa_printf(MSG_DEBUG, "VLAN: Set interface %s up", if_name);
	return ifconfig_helper(if_name, 1);
}


int iface_exists(const char *ifname)
{
	return if_nametoindex(ifname);
}

#endif /* CONFIG_NATIVE_WINDOWS */
