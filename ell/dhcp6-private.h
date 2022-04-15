/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

struct l_dhcp6_client;

enum {
	DHCP6_PORT_SERVER = 547,
	DHCP6_PORT_CLIENT = 546,
};

enum {
	DHCP6_OPTION_CLIENT_ID			= 1,
	DHCP6_OPTION_SERVER_ID			= 2,
	DHCP6_OPTION_IA_NA			= 3,
	DHCP6_OPTION_IA_TA			= 4,
	DHCP6_OPTION_IA_ADDR			= 5,
	DHCP6_OPTION_REQUEST_OPTION		= 6,
	DHCP6_OPTION_PREFERENCE			= 7,
	DHCP6_OPTION_ELAPSED_TIME		= 8,
	DHCP6_OPTION_STATUS_CODE		= 13,
	DHCP6_OPTION_RAPID_COMMIT		= 14,
	DHCP6_OPTION_USER_CLASS			= 15,
	DHCP6_OPTION_VENDOR_CLASS		= 16,
	DHCP6_OPTION_VENDOR_OPTS		= 17,
	DHCP6_OPTION_IA_PD			= 25,
	DHCP6_OPTION_IA_PREFIX			= 26,
	DHCP6_OPTION_INF_RT			= 32,
	DHCP6_OPTION_SOL_MAX_RT			= 82,
	DHCP6_OPTION_INF_MAX_RT			= 83,
};

#define DHCP6_ADDR_LINKLOCAL_ALL_NODES \
	{ { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 } } }

/* RFC 8415, Section 11.1 */
enum duid_type {
	DUID_TYPE_LINK_LAYER_ADDR_PLUS_TIME	= 1,
	DUID_TYPE_ENTERPRISE_NUMBER		= 2,
	DUID_TYPE_LINK_LAYER_ADDR		= 3,
	DUID_TYPE_UNIVERSALLY_UNIQUE_ID		= 4,
};

struct duid {
	__be16 type;
	uint8_t identifier[];
} __attribute__ ((packed));

/* RFC 8415, Figure 2 */
struct dhcp6_message {
	union {
		uint8_t msg_type;
		__be32 transaction_id;
	};
	uint8_t options[];
} __attribute__ ((packed));

struct dhcp6_option_iter {
	const uint8_t *options;
	uint16_t pos;
	uint16_t max;
};

typedef void (*dhcp6_transport_rx_cb_t)(const void *, size_t, uint64_t, void *);

struct dhcp6_transport {
	int (*open)(struct dhcp6_transport *s);
	int (*send)(struct dhcp6_transport *transport,
						const struct in6_addr *dest,
						const void *data, size_t len);
	void (*close)(struct dhcp6_transport *transport);
	uint32_t ifindex;
	dhcp6_transport_rx_cb_t rx_cb;
	void *rx_data;
};

struct dhcp6_transport *_dhcp6_default_transport_new(uint32_t ifindex,
						const struct in6_addr *addr,
						uint16_t port);
void _dhcp6_transport_free(struct dhcp6_transport *transport);
void _dhcp6_transport_set_rx_callback(struct dhcp6_transport *transport,
					dhcp6_transport_rx_cb_t rx_cb,
					void *userdata);

void __dhcp6_option_iter_init(struct dhcp6_option_iter *iter,
				const void *options, size_t len);
bool _dhcp6_option_iter_init(struct dhcp6_option_iter *iter,
				const struct dhcp6_message *message,
				size_t len);
bool _dhcp6_option_iter_next(struct dhcp6_option_iter *iter, uint16_t *type,
				uint16_t *len, const void **data);

bool _dhcp6_client_set_transport(struct l_dhcp6_client *client,
					struct dhcp6_transport *transport);

struct dhcp6_address_info {
	uint8_t addr[16];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
	uint8_t prefix_len;
};

struct dhcp6_ia {
	uint8_t iaid[4];
	uint32_t t1;
	uint32_t t2;
	struct dhcp6_address_info info;
};

struct l_dhcp6_lease {
	uint8_t *server_id;
	size_t server_id_len;
	uint8_t preference;
	uint64_t start_time;

	struct dhcp6_ia ia_na;
	struct dhcp6_ia ia_pd;
	uint8_t *dns;
	uint16_t dns_len;
	char **domain_list;

	bool have_na : 1;
	bool have_pd : 1;
	bool rapid_commit : 1;
};

struct l_dhcp6_lease *_dhcp6_lease_new(void);
void _dhcp6_lease_free(struct l_dhcp6_lease *lease);
struct l_dhcp6_lease *_dhcp6_lease_parse_options(
					struct dhcp6_option_iter *iter,
					const uint8_t expected_iaid[static 4]);
uint32_t _dhcp6_lease_get_t1(const struct l_dhcp6_lease *lease);
uint32_t _dhcp6_lease_get_t2(const struct l_dhcp6_lease *lease);
