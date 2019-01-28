/**
 * @file layer2.h
 *
 * @brief Layer 2 handling.
 * @author David Suárez
 * @date Sun, 28 Oct 2018 16:14:56 +0100
 *
 * Copyright (c) 2018 David Suárez.
 * Email: david.sephirot@gmail.com
 *
 */


#ifndef __LAYER2_H__
#define __LAYER2_H__

#include "compat/compat.h"

#include "pcap_engine.h" /* for datalink_info_t */

#define ETH_ALEN 6 
#define ETH_HLAN 14 
#define ETH_ZLEN 60 
#define ETH_DATA_LEN 1500 
#define ETH_FRAME_LEN 1514 
#define ETH_FCS_LEN 4  
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define ETH_P_PAE 0x888E

struct ethhdr
{
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    unsigned short h_proto;
}__attribute__((packed));
/**
 * handle_link_layer:
 *
 * Handles the data link layer (layer 2) returning information of the next layer 3 protocol
 * and the offset in the packet.
 *
 * @param[in] info data link information.
 * @param[in] pkt the captured packet.
 * @param[in] caplen the length of the captured packet.
 * @param[out] nextproto the protocol of next header (as IP protocol).
 * @param[out] offsetnext the offset of next header in packet.
 *
 * @return 0 if OK, -1 if error / unsupported proto
 */
int handle_link_layer(datalink_info_t *info, const u_char *pkt, uint32_t caplen,
		uint8_t *nextproto, int *offsetnext);

#endif /* __LAYER2_H__ */
