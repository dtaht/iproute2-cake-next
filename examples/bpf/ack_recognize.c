/*
 * Copyright 2017 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * Author: dave.taht@gmail.com (Dave Taht)
 *
 * ack_recognizer: An eBPF program that correctly recognizes modern TCP ACKs,
 * with tcp option fields like SACK and timestamps, and no additional data.
 *
 * ack_match: Recognize "pure acks" with no data payload
 *
 */

#include "bpf_api.h"
#include "linux/if_ether.h"
#include "linux/ip.h"
#include "linux/in.h"
#include "linux/ipv6.h"
#include "linux/tcp.h"

/*
 * A pure ack contains the ip header, the tcp header + options, flags with the
 * ack field set, and no additional payload. That last bit is what every prior
 * ack filter gets wrong, they typically assume an obsolete 64 bytes, and don't
 * calculate the options (like sack or timestamps) to subtract from the payload.
 */

__section_cls_entry
int ack_match(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);
	struct tcphdr *tcp;

	if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcp) > data_end)
		return 0;

	if (eth->h_proto == htons(ETH_P_IP) &&
	    iph->version == 4) {
		if(iph->protocol == IPPROTO_TCP &&
		   iph->ihl == 5 &&
		   data + sizeof(*eth) + 20 + sizeof(*tcp) <= data_end) {
			tcp = data + sizeof(*eth) + 20;
			if (tcp->ack &&
			    htons(iph->tot_len) == 20 + tcp->doff*4)
				return -1;
		}
	} else if (eth->h_proto == htons(ETH_P_IPV6) &&
		   iph->version == 6) {
		struct ipv6hdr *iph6 = (struct ipv6hdr *) iph;
		if(iph6->nexthdr == IPPROTO_TCP &&
		   data + sizeof(*eth) + 40 + sizeof(*tcp) <= data_end ) {
			tcp = data + sizeof(*eth) + 40;
			if (tcp->ack &&
			    tcp->doff*4 == htons(iph6->payload_len))
				return -1;
		}
	}

	return 0;
}

/* Example: Move acks into a priority queue:

tc qdisc del dev $IFACE root 2> /dev/null
tc qdisc add dev $IFACE root handle 1: prio bands 3 \
	priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev $IFACE parent 1:1 handle 10:1 sfq headdrop # acks only
tc qdisc add dev $IFACE parent 1:2 handle 20:1 fq_codel # all other traffic
tc qdisc add dev $IFACE parent 1:3 handle 30:1 fq_codel # unused
tc filter add dev $IFACE parent 1: prio 1 bpf \
	object-file ack_recognize.o flowid 1:1

Please note that a strict priority queue is not a good idea (drr would be
better), nor is doing any level of prioritization on acks at all....
*/

BPF_LICENSE("GPL");
