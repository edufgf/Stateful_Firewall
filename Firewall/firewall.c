#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "headers.h"
#include "network.h"

#define IN_TIMEOUT 1
#define OUT_TIMEOUT 1
#define MAX_INPUT_LINES 7

int ONLINE;

int NEXT_TCP_PORT;
int NEXT_UDP_PORT;

rule_list rules_table;
hash_node state_table[3][TABLE_SIZE];
uint16_t port_map[2][2][PORT_RANGE];

int device_not_found(char *dev, char* errbuf){
	pcap_if_t *dev_list;
	if (pcap_findalldevs(&dev_list, errbuf)==-1){
			printf("%s\n",errbuf);
	    exit(1);
	}
	pcap_if_t *dev_it;
	for (dev_it = dev_list; dev_it != NULL; dev_it = dev_it->next)
		if (match_name(dev_it->name, dev)) return 0;
	return 1;
}

int setup_firewall(firewall_t* fwall, char* in, char* out, char* errbuf) {
	FILE *settings;
	settings = fopen("settings.config", "r");

	if (settings == NULL) {
		return 0;
	}
	
	int read = 0;
	char buff[1024];
	while (fgets(buff, 1024, settings) != NULL) {
		int str_tam = strlen(buff);
  	if (read == 0) {
  		str_to_mac(buff, fwall->virtual_mac); 	
  	} else if (read == 1) {
  		str_to_mac(buff, fwall->firewall_mac);
  	} else if (read == 2) {
  		str_to_mac(buff, fwall->switch_mac);
  	} else if (read == 3) {
  		str_to_mac(buff, fwall->router_mac);
  	} else if (read == 4) {
  		fwall->virtual_ip_str = (char*) malloc(str_tam+1);
  		memcpy(fwall->virtual_ip_str, buff, str_tam);
  		fwall->virtual_ip_str[str_tam] = 0;
  		str_to_ip(fwall->virtual_ip_str, fwall->virtual_ip_bin);		
  	} else if (read == 5) {
  		fwall->firewall_ip_str = (char*) malloc(str_tam+1);
  		memcpy(fwall->firewall_ip_str, buff, str_tam);
  		fwall->firewall_ip_str[str_tam] = 0;
  		str_to_ip(fwall->firewall_ip_str, fwall->firewall_ip_bin);
  	} else if (read == 6) {
  		fwall->switch_ip_str = (char*) malloc(str_tam+1);
  		memcpy(fwall->switch_ip_str, buff, str_tam);
  		fwall->switch_ip_str[str_tam] = 0;
  		str_to_ip(fwall->switch_ip_str, fwall->switch_ip_bin);
  	}
  	read++;
		if (read == MAX_INPUT_LINES)
			break;
	}
	
	if (read != MAX_INPUT_LINES) {
		fclose(settings);
		return 0;
	}
	
	int sz = strlen(in);
	fwall->dev_name_in = (char*) malloc(sz);
	memcpy(fwall->dev_name_in, in, sz);
	sz = strlen(out);
	fwall->dev_name_out = (char*) malloc(sz);
	memcpy(fwall->dev_name_out, out, sz);
	
	fwall->pcap_in_timeout = IN_TIMEOUT;
	fwall->pcap_out_timeout = OUT_TIMEOUT;
	
	NEXT_TCP_PORT = HIGH_PORT;
  NEXT_UDP_PORT = HIGH_PORT;
	
	ONLINE = 1;
	int i;
	for (i=0;i<strlen(fwall->dev_name_in);i++)
		if (fwall->dev_name_in[i] == '.') ONLINE = 0;
	
	if (ONLINE) {	
		if (device_not_found(in, errbuf)) {
			printf("Device %s not found!\n",in);
			return 0;
		}	
		if (device_not_found(out, errbuf)) {
			printf("Device %s not found!\n",out);
			return 0;
		}	
		
		fwall->pcap_in = pcap_open_live(fwall->dev_name_in, BUFSIZ, 0, fwall->pcap_in_timeout, errbuf);	
		if (fwall->pcap_in == NULL) {
			printf("Error pcap in: %s\n", errbuf);
			return 0;
		}
		if (pcap_datalink(fwall->pcap_in) != 1) {
			printf("Not ethernet data-link pcap in!\n");
			return 0;
		}
	
		fwall->pcap_out = pcap_open_live(fwall->dev_name_out, BUFSIZ, 0, fwall->pcap_out_timeout, errbuf);	
		if (fwall->pcap_out == NULL) {
			printf("Error pcap out: %s\n", errbuf);
			return 0;
		}
		if (pcap_datalink(fwall->pcap_out) != 1) {
			printf("Not ethernet data-link pcap out!\n");
			return 0;
		}
	} else {
		fwall->pcap_in = pcap_open_offline(fwall->dev_name_in, errbuf);	
		if (fwall->pcap_in == NULL) {
			printf("Error pcap in: %s\n", errbuf);
			return 0;
		}
		if (pcap_datalink(fwall->pcap_in) != 1) {
			printf("Not ethernet data-link pcap in!\n");
			return 0;
		}
	
		fwall->pcap_out = pcap_open_offline(fwall->dev_name_out, errbuf);	
		if (fwall->pcap_out == NULL) {
			printf("Error pcap out: %s\n", errbuf);
			return 0;
		}
		if (pcap_datalink(fwall->pcap_out) != 1) {
			printf("Not ethernet data-link pcap out!\n");
			return 0;
		}
	}
	
	fclose(settings);
	return 1;
}

uint16_t get_port(uint16_t port, int type, int dir) {
	int i;
	if (type == TCP) {
			for (i=0;i<PORT_RANGE;i++){
				if (port_map[type][dir][i] == 0)
					break;
				if (port_map[type][dir][i] == port) {
					return port_map[type][(dir+1)%2][i];	
				}	
			}
			if (i == PORT_RANGE){
				printf("Out of ports!\n");
				return 0;
			}
			port_map[type][dir][i] = port;
			port_map[type][(dir+1)%2][i] = NEXT_TCP_PORT;
			return NEXT_TCP_PORT++;
	} else if (type == UDP) {
		for (i=0;i<PORT_RANGE;i++){
				if (port_map[type][dir][i] == 0)
					break;
				if (port_map[type][dir][i] == port) {
					return port_map[type][(dir+1)%2][i];	
				}	
			}
			if (i == PORT_RANGE){
				printf("Out of ports!\n");
				return 0;
			}
			port_map[type][dir][i] = port;
			port_map[type][(dir+1)%2][i] = NEXT_UDP_PORT;
			return NEXT_UDP_PORT++;
	}
}

int NAT_TCP(firewall_t* fwall, ethernet_hdr_t* ethernet_header, ip_hdr_t* ip_header, tcp_hdr_t* tcp_header, int dir) {
	if (dir == OUT) {
		memcpy(ethernet_header->src_mac, fwall->switch_mac, sizeof(fwall->switch_mac));
		memcpy(ethernet_header->dst_mac, fwall->router_mac, sizeof(fwall->router_mac));
		memcpy(ip_header->src_ip, fwall->switch_ip_bin, sizeof(fwall->switch_ip_bin));
		compute_ip_checksum(ip_header);	
		
	  uint16_t new_src_port = get_port(unpack_2byte(tcp_header->src_port), TCP, dir);
		new_src_port = pack_2byte((uint8_t*)&new_src_port);
	  memcpy(tcp_header->src_port, (uint8_t*)&new_src_port, sizeof(uint16_t));
		
		pseudo_tcp_hdr_t* pseudo_tcp_header = (pseudo_tcp_hdr_t*) malloc(sizeof(pseudo_tcp_hdr_t));
		
		memcpy(pseudo_tcp_header->src_ip, ip_header->src_ip, sizeof(ip_header->src_ip));
		memcpy(pseudo_tcp_header->dst_ip, ip_header->dst_ip, sizeof(ip_header->dst_ip));
		pseudo_tcp_header->reserved = 0;
		pseudo_tcp_header->protocol = ip_header->protocol;
		uint16_t len = unpack_2byte(ip_header->total_len) - ((ip_header->version_ihl & 0x0F)*4);
		pseudo_tcp_header->tcp_len[0] = ((uint8_t)(len>>8)) & 0xFF;
		pseudo_tcp_header->tcp_len[1] = (uint8_t)(len) & 0xFF;
		
		pseudo_tcp_header->tcp_header = (tcp_hdr_t*) malloc(len);
		memcpy(pseudo_tcp_header->tcp_header, tcp_header, len);
		compute_tcp_checksum(pseudo_tcp_header);
		memcpy(tcp_header->checksum, pseudo_tcp_header->tcp_header->checksum, sizeof(tcp_header->checksum));
		free(pseudo_tcp_header->tcp_header);
		free(pseudo_tcp_header);
	} else if (dir == IN) {
		memcpy(ethernet_header->src_mac, fwall->firewall_mac, sizeof(fwall->firewall_mac));
		memcpy(ethernet_header->dst_mac, fwall->virtual_mac, sizeof(fwall->virtual_mac));
		memcpy(ip_header->dst_ip, fwall->virtual_ip_bin, sizeof(fwall->virtual_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_dst_port = get_port(unpack_2byte(tcp_header->dst_port), TCP, dir);
		new_dst_port = pack_2byte((uint8_t*)&new_dst_port);
	  memcpy(tcp_header->dst_port, (uint8_t*)&new_dst_port, sizeof(uint16_t));
		
		pseudo_tcp_hdr_t* pseudo_tcp_header = (pseudo_tcp_hdr_t*) malloc(sizeof(pseudo_tcp_hdr_t));
		
		memcpy(pseudo_tcp_header->src_ip, ip_header->src_ip, sizeof(ip_header->src_ip));
		memcpy(pseudo_tcp_header->dst_ip, ip_header->dst_ip, sizeof(ip_header->dst_ip));
		pseudo_tcp_header->reserved = 0;
		pseudo_tcp_header->protocol = ip_header->protocol;
		uint16_t len = unpack_2byte(ip_header->total_len) - ((ip_header->version_ihl & 0x0F)*4);
		pseudo_tcp_header->tcp_len[0] = ((uint8_t)(len>>8)) & 0xFF;
		pseudo_tcp_header->tcp_len[1] = (uint8_t)(len) & 0xFF;
		
		pseudo_tcp_header->tcp_header = (tcp_hdr_t*) malloc(len);
		memcpy(pseudo_tcp_header->tcp_header, tcp_header, len);
		compute_tcp_checksum(pseudo_tcp_header);
		memcpy(tcp_header->checksum, pseudo_tcp_header->tcp_header->checksum, sizeof(tcp_header->checksum));
		free(pseudo_tcp_header->tcp_header);
		free(pseudo_tcp_header);
	}
	return 1;
}

int NAT_UDP(firewall_t* fwall, ethernet_hdr_t* ethernet_header, ip_hdr_t* ip_header, udp_hdr_t* udp_header, int dir) {
	if (dir == OUT) {
		memcpy(ethernet_header->src_mac, fwall->switch_mac, sizeof(fwall->switch_mac));
		memcpy(ethernet_header->dst_mac, fwall->router_mac, sizeof(fwall->router_mac));
		memcpy(ip_header->src_ip, fwall->switch_ip_bin, sizeof(fwall->switch_ip_bin));
		compute_ip_checksum(ip_header);	
		
	  uint16_t new_src_port = get_port(unpack_2byte(udp_header->src_port), UDP, dir);
		new_src_port = pack_2byte((uint8_t*)&new_src_port);
	  memcpy(udp_header->src_port, (uint8_t*)&new_src_port, sizeof(uint16_t));
		
		pseudo_udp_hdr_t* pseudo_udp_header = (pseudo_udp_hdr_t*) malloc(sizeof(pseudo_udp_hdr_t));
		
		memcpy(pseudo_udp_header->src_ip, ip_header->src_ip, sizeof(ip_header->src_ip));
		memcpy(pseudo_udp_header->dst_ip, ip_header->dst_ip, sizeof(ip_header->dst_ip));
		pseudo_udp_header->reserved = 0;
		pseudo_udp_header->protocol = ip_header->protocol;
		uint16_t len = unpack_2byte(udp_header->len);
		pseudo_udp_header->udp_len[0] = udp_header->len[0];
		pseudo_udp_header->udp_len[1] = udp_header->len[1];
		
		pseudo_udp_header->udp_header = (udp_hdr_t*) malloc(len);
		memcpy(pseudo_udp_header->udp_header, udp_header, len);
		compute_udp_checksum(pseudo_udp_header);
		memcpy(udp_header->checksum, pseudo_udp_header->udp_header->checksum, sizeof(udp_header->checksum));
		free(pseudo_udp_header->udp_header);
		free(pseudo_udp_header);
	} else if (dir == IN) {
		memcpy(ethernet_header->src_mac, fwall->firewall_mac, sizeof(fwall->firewall_mac));
		memcpy(ethernet_header->dst_mac, fwall->virtual_mac, sizeof(fwall->virtual_mac));
		memcpy(ip_header->dst_ip, fwall->virtual_ip_bin, sizeof(fwall->virtual_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_dst_port = get_port(unpack_2byte(udp_header->dst_port), UDP, dir);
		new_dst_port = pack_2byte((uint8_t*)&new_dst_port);
	  memcpy(udp_header->dst_port, (uint8_t*)&new_dst_port, sizeof(uint16_t));
		
		pseudo_udp_hdr_t* pseudo_udp_header = (pseudo_udp_hdr_t*) malloc(sizeof(pseudo_udp_hdr_t));
		
		memcpy(pseudo_udp_header->src_ip, ip_header->src_ip, sizeof(ip_header->src_ip));
		memcpy(pseudo_udp_header->dst_ip, ip_header->dst_ip, sizeof(ip_header->dst_ip));
		pseudo_udp_header->reserved = 0;
		pseudo_udp_header->protocol = ip_header->protocol;
		uint16_t len = unpack_2byte(udp_header->len);
		pseudo_udp_header->udp_len[0] = udp_header->len[0];
		pseudo_udp_header->udp_len[1] = udp_header->len[1];
		
		pseudo_udp_header->udp_header = (udp_hdr_t*) malloc(len);
		memcpy(pseudo_udp_header->udp_header, udp_header, len);
		compute_udp_checksum(pseudo_udp_header);
		memcpy(udp_header->checksum, pseudo_udp_header->udp_header->checksum, sizeof(udp_header->checksum));
		free(pseudo_udp_header->udp_header);
		free(pseudo_udp_header);
	}
	return 1;
}

void NAT_ICMP(firewall_t* fwall, ethernet_hdr_t* ethernet_header, ip_hdr_t* ip_header, int dir) {
	if (dir == OUT) {
		memcpy(ethernet_header->src_mac, fwall->switch_mac, sizeof(fwall->switch_mac));
		memcpy(ethernet_header->dst_mac, fwall->router_mac, sizeof(fwall->router_mac));
		memcpy(ip_header->src_ip, fwall->switch_ip_bin, sizeof(fwall->switch_ip_bin));
		compute_ip_checksum(ip_header);	
	} else if (dir == IN) {
		memcpy(ethernet_header->src_mac, fwall->firewall_mac, sizeof(fwall->firewall_mac));
		memcpy(ethernet_header->dst_mac, fwall->virtual_mac, sizeof(fwall->virtual_mac));
		memcpy(ip_header->dst_ip, fwall->virtual_ip_bin, sizeof(fwall->virtual_ip_bin));
		compute_ip_checksum(ip_header);
	}
}

void build_ARP_reply(firewall_t* fwall, arp_hdr_t* arp_header) {
	arp_hdr_t* arp_header_cpy = arp_header_copy(arp_header);				
	uint16_t arp_operation = 2;
	uint8_t arp_op_reply[2];
	arp_op_reply[0] = 0;
	arp_op_reply[1] = (uint8_t) arp_operation & 0xFF;

	memcpy(arp_header->operation, arp_op_reply, sizeof(arp_op_reply));
	memcpy(arp_header->sender_hardware_addr, fwall->firewall_mac, sizeof(fwall->firewall_mac));
	memcpy(arp_header->sender_protocol_addr, arp_header_cpy->target_protocol_addr, sizeof(arp_header_cpy->target_protocol_addr));
	memcpy(arp_header->target_hardware_addr, arp_header_cpy->sender_hardware_addr, sizeof(arp_header_cpy->sender_hardware_addr));
	memcpy(arp_header->target_protocol_addr, arp_header_cpy->sender_protocol_addr, sizeof(arp_header_cpy->sender_protocol_addr));
	
	free(arp_header_cpy);
}

int setup_rules(firewall_t* fwall) {
	int i, j;
	for (i=0;i<3;i++) {
		for (j=0;j<TABLE_SIZE;j++){
			state_table[i][j].len = 0;
			state_table[i][j].head = NULL;
		}
	}
	for (i=0;i<PORT_RANGE;i++) {
		port_map[TCP][IN][i] = 0;
		port_map[TCP][OUT][i] = 0;
		port_map[UDP][IN][i] = 0;
		port_map[UDP][OUT][i] = 0;
	}
	rules_table.len = 0;
	rules_table.head = NULL;
	rules_table.tail = NULL;
	
	FILE *rules;
	rules = fopen("default.rules", "r");

	if (rules == NULL) {
		return 0;
	}
	
	char buff[1024];
	char rule[32], dir[32], service[32];
	char ip_src[32], ip_dst[32], port_src[32], port_dst[32];
	int rule_cnt = 0;
	
	uint8_t ip_bin[4];
	while (fgets(buff, 1024, rules) != NULL) {
		rule_cnt++;
  	sscanf(buff, "%s %s %s %s %s %*s %s %s", rule, dir, service, ip_src, port_src, ip_dst, port_dst);
  	
  	rule_elem* new_rule = (rule_elem*) malloc(sizeof(rule_elem));
  	new_rule->src_ip_any = 0;
  	new_rule->dst_ip_any = 0;
  	new_rule->src_port_any = 0;
  	new_rule->dst_port_any = 0;

		// Rule
		if (match_name(rule, "block"))
			new_rule->rule = BLOCK;
		else if (match_name(rule, "allow"))
			new_rule->rule = ALLOW;
		else {
			printf("Bad Rule Syntax, number #%d\n", rule_cnt);
			free(new_rule);
  		continue;
		}
		
		// Direction
		if (match_name(dir, "in"))
			new_rule->dir = IN;
		else if (match_name(dir, "out"))
			new_rule->dir = OUT;
		else {
			printf("Bad Rule Syntax, number #%d\n", rule_cnt);
			free(new_rule);
  		continue;
		}
		
		// Service
		new_rule->service = service_map(service);
  	if (new_rule->service == -1) {
  		printf("Bad Rule Syntax, number #%d\n", rule_cnt);
  		free(new_rule);
  		continue;
  	}
			
  	// IP Source
  	if (match_name(ip_src, "HOME")) {
  		memcpy(ip_src, fwall->virtual_ip_str, strlen(fwall->virtual_ip_str)+1);
  	}
  	if (match_name(ip_src, "any")) {
  		new_rule->src_ip_any = 1;	
  	} else {
  		str_to_ip(ip_src, ip_bin);
			new_rule->src_ip = unpack_4byte(ip_bin);
  	}
  	
  	// Port Source
  	if (match_name(port_src, "any")) {
  		new_rule->src_port_any = 1;	
  	} else {
  		new_rule->src_port = atoi(port_src);
  	}
  	
  	// IP Dest
  	if (match_name(ip_dst, "HOME")) {
  		memcpy(ip_dst, fwall->virtual_ip_str, strlen(fwall->virtual_ip_str)+1);
  	}
  	if (match_name(ip_dst, "any")) {
  		new_rule->dst_ip_any = 1;	
  	} else {
  		str_to_ip(ip_dst, ip_bin);
			new_rule->dst_ip = unpack_4byte(ip_bin);
  	}
  	
  	// Port Dest
  	if (match_name(port_dst, "any")) {
  		new_rule->dst_port_any = 1;	
  	} else {
  		new_rule->dst_port = atoi(port_dst);
  	}

  	insert_rule(new_rule);
	}
	return 1;
}


void listen_in(firewall_t* fwall) {
	const uint8_t* packet = NULL;
	struct pcap_pkthdr* header = NULL;		
	
	int ret = pcap_next_ex(fwall->pcap_in, &header, &packet);
	if (ret == -2) return;
	if (packet == NULL) return;
	
	ethernet_hdr_t* ethernet_header = (ethernet_hdr_t*)packet;
	uint16_t ethertype = unpack_2byte(ethernet_header->ethertype);
	struct timeval current_time = header->ts;
	
	#ifdef DEBUGGING
		print_ethernet(ethernet_header, "in");
	#endif
	
	if (ethertype == ETHERTYPE_IP) {
		ip_hdr_t* ip_header = (ip_hdr_t*)ethernet_header->data;	
		int protocol = ip_header->protocol;
		ip_tuple ip;
		ip_tuple inv_ip;
		ip_port_tuple ip_port;
		ip_port_tuple inv_ip_port;
		
		#ifdef DEBUGGING
			print_ip_packet(ip_header, "in");
		#endif
		
		if (address_equal_ip(fwall->virtual_ip_bin, ip_header->src_ip)) { //A packet from virtual machine to be sent to external world
			ip.src_ip = unpack_4byte(ip_header->src_ip);
			ip.dst_ip = unpack_4byte(ip_header->dst_ip);
			inv_ip.src_ip = ip.dst_ip;
			inv_ip.dst_ip = ip.src_ip;
			
			if (protocol == 6) { // TCP
				tcp_stats A;
				tcp_stats A_inv;
				void* table_entry;
				int ihl = ip_header->version_ihl & 0x0F;
				tcp_hdr_t* tcp_header = (tcp_hdr_t*)(&ip_header->version_ihl + ihl*4);
				
				ip_port.src_ip = ip.src_ip;
				ip_port.dst_ip = ip.dst_ip;
				ip_port.src_port = unpack_2byte(tcp_header->src_port);
				ip_port.dst_port = unpack_2byte(tcp_header->dst_port);

				inv_ip_port.src_ip = ip.dst_ip;
				inv_ip_port.dst_ip = ip.src_ip;
				inv_ip_port.src_port = ip_port.dst_port;
				inv_ip_port.dst_port = ip_port.src_port;
				
				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				NAT_TCP(fwall, ethernet_header, ip_header, tcp_header, OUT);
		
				table_entry = state_table_find(state_table[TCP], (void*)&A_inv, TCP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A_inv, tcp_header->flags, 1))
						return;
					state_table_update(table_entry, (void*)&A_inv, TCP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/TCP");			
					return;	
				}
				
				table_entry = state_table_find(state_table[TCP], (void*)&A, TCP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A, tcp_header->flags, 0))
						return;
					state_table_update(table_entry, (void*)&A, TCP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/TCP");	
					return;		
				}

				if (!check_rule(OUT, TCP, ip.src_ip, ip.dst_ip, ip_port.src_port, ip_port.dst_port)) // Blocked by firewall, drop the packet.
					return; 
	
				if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A, tcp_header->flags, 0))
						return;
				state_table_insert(state_table[TCP], (void*)&A, TCP); // New TCP state
				packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/TCP");
				return;
			} else if (protocol == 17) {  // UDP
				udp_stats A;
				udp_stats A_inv;
				void* table_entry;
				int ihl = ip_header->version_ihl & 0x0F;
				udp_hdr_t* udp_header = (udp_hdr_t*)(&ip_header->version_ihl + ihl*4);
				
				ip_port.src_ip = ip.src_ip;
				ip_port.dst_ip = ip.dst_ip;
				ip_port.src_port = unpack_2byte(udp_header->src_port);
				ip_port.dst_port = unpack_2byte(udp_header->dst_port);
				
				inv_ip_port.src_ip = ip.dst_ip;
				inv_ip_port.dst_ip = ip.src_ip;
				inv_ip_port.src_port = ip_port.dst_port;
				inv_ip_port.dst_port = ip_port.src_port;
				
				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				NAT_UDP(fwall, ethernet_header, ip_header, udp_header, OUT);
	
				table_entry = state_table_find(state_table[UDP], (void*)&A_inv, UDP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, UDP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/UDP");			
					return;	
				}
				
				table_entry = state_table_find(state_table[UDP], (void*)&A, UDP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, UDP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/UDP");	
					return;		
				}

				if (!check_rule(OUT, UDP, ip.src_ip, ip.dst_ip, ip_port.src_port, ip_port.dst_port)) // Blocked by firewall, drop the packet.
					return; 
				
				state_table_insert(state_table[UDP], (void*)&A, UDP); // UDP state
				packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/UDP");
				return;
			} else if (protocol == 1) {   // ICMP
				icmp_stats A;
				icmp_stats A_inv;
				void* table_entry;
				
				A.ip = ip;
				A_inv.ip = inv_ip;
				A.event_time = current_time;
				A_inv.event_time = current_time;
				
				NAT_ICMP(fwall, ethernet_header, ip_header, OUT);
				
				table_entry = state_table_find(state_table[ICMP], (void*)&A_inv, ICMP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, ICMP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/ICMP");			
					return;	
				}
				
				table_entry = state_table_find(state_table[ICMP], (void*)&A, ICMP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, ICMP);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/ICMP");	
					return;		
				}

				if (!check_rule(OUT, ICMP, ip.src_ip, ip.dst_ip, 0, 0)) // Blocked by firewall, drop the packet.
					return; 
				
				state_table_insert(state_table[ICMP], (void*)&A, ICMP); // ICMP state
				packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/ICMP");
				
				return;
			} else {											// Other protocol, drop
				return;	
			}
		}
	
	}
	
	if (ethertype == ETHERTYPE_ARP) {
		arp_hdr_t* arp_header = (arp_hdr_t*)ethernet_header->data;
		uint16_t arp_operation = unpack_2byte(arp_header->operation);
		if (arp_operation == 1) {			  // Arp request
			if (address_equal_ip(fwall->firewall_ip_bin, arp_header->target_protocol_addr)) { //ARP request for firewall IP
					build_ARP_reply(fwall, arp_header);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/ARP"); // Send ARP reply to VM
					return;
			}
		} 
	}

}

void listen_out(firewall_t* fwall) {
	const uint8_t* packet = NULL;
	struct pcap_pkthdr* header = NULL;	
	
	int ret = pcap_next_ex(fwall->pcap_out, &header, &packet);
	if (ret == -2) return;
	if (packet == NULL) return;
	
	ethernet_hdr_t* ethernet_header = (ethernet_hdr_t*)packet;
	uint16_t ethertype = unpack_2byte(ethernet_header->ethertype);
	struct timeval current_time = header->ts;
	
	#ifdef DEBUGGING
		print_ethernet(ethernet_header, "out");
	#endif
	
	if (ethertype == ETHERTYPE_IP) {
		ip_hdr_t* ip_header = (ip_hdr_t*)ethernet_header->data;	
		int protocol = ip_header->protocol;
		ip_tuple ip;
		ip_tuple inv_ip;
		ip_port_tuple ip_port;
		ip_port_tuple inv_ip_port;
				
		#ifdef DEBUGGING
			print_ip_packet(ip_header, "out");
		#endif

		if (address_equal_ip(fwall->switch_ip_bin, ip_header->dst_ip)) { //Switch gets a packet for it, let's send to VM if allowed. 
			if (protocol == 6) { // TCP
				tcp_stats A;
				tcp_stats A_inv;
				void* table_entry;
				
				int ihl = ip_header->version_ihl & 0x0F;
				tcp_hdr_t* tcp_header = (tcp_hdr_t*)(&ip_header->version_ihl + ihl*4);
				
				if (NAT_TCP(fwall, ethernet_header, ip_header, tcp_header, IN)==0) return;
				
				ip.src_ip = unpack_4byte(ip_header->src_ip);
				ip.dst_ip = unpack_4byte(ip_header->dst_ip);
				inv_ip.src_ip = ip.dst_ip;
				inv_ip.dst_ip = ip.src_ip;
				
				ip_port.src_ip = ip.src_ip;
				ip_port.dst_ip = ip.dst_ip;
				ip_port.src_port = unpack_2byte(tcp_header->src_port);
				ip_port.dst_port = unpack_2byte(tcp_header->dst_port);
				
				inv_ip_port.src_ip = ip.dst_ip;
				inv_ip_port.dst_ip = ip.src_ip;
				inv_ip_port.src_port = ip_port.dst_port;
				inv_ip_port.dst_port = ip_port.src_port;

				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;
				
				table_entry = state_table_find(state_table[TCP], (void*)&A_inv, TCP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A_inv, tcp_header->flags, 1))
						return;
					state_table_update(table_entry, (void*)&A_inv, TCP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/TCP");				
					return;	
				}
				
				table_entry = state_table_find(state_table[TCP], (void*)&A, TCP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A, tcp_header->flags, 0))
						return;
					state_table_update(table_entry, (void*)&A, TCP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/TCP");		
					return;		
				}

				if (!check_rule(IN, TCP, ip.src_ip, ip.dst_ip, ip_port.src_port, ip_port.dst_port)) // Blocked by firewall, drop the packet.
					return; 

				if (!TCP_check_state((tcp_stats*)table_entry, (tcp_stats*)&A, tcp_header->flags, 0))
						return;
				state_table_insert(state_table[TCP], (void*)&A, TCP); // New TCP state
				packet_inject(fwall->pcap_in, packet, header->caplen,"IN/TCP");	
				return;
			} else if (protocol == 17) {  // UDP
				udp_stats A;
				udp_stats A_inv;
				void* table_entry;
				
				int ihl = ip_header->version_ihl & 0x0F;
				udp_hdr_t* udp_header = (udp_hdr_t*)(&ip_header->version_ihl + ihl*4);
				
				if (NAT_UDP(fwall, ethernet_header, ip_header, udp_header, IN)==0) return;
				
				ip.src_ip = unpack_4byte(ip_header->src_ip);
				ip.dst_ip = unpack_4byte(ip_header->dst_ip);
				inv_ip.src_ip = ip.dst_ip;
				inv_ip.dst_ip = ip.src_ip;
				
				ip_port.src_ip = ip.src_ip;
				ip_port.dst_ip = ip.dst_ip;
				ip_port.src_port = unpack_2byte(udp_header->src_port);
				ip_port.dst_port = unpack_2byte(udp_header->dst_port);
				
				inv_ip_port.src_ip = ip.dst_ip;
				inv_ip_port.dst_ip = ip.src_ip;
				inv_ip_port.src_port = ip_port.dst_port;
				inv_ip_port.dst_port = ip_port.src_port;
				
				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;
				
				table_entry = state_table_find(state_table[UDP], (void*)&A_inv, UDP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, UDP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/UDP");				
					return;	
				}
				
				table_entry = state_table_find(state_table[UDP], (void*)&A, UDP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, UDP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/UDP");		
					return;		
				}

				if (!check_rule(IN, UDP, ip.src_ip, ip.dst_ip, ip_port.src_port, ip_port.dst_port)) // Blocked by firewall, drop the packet.
					return; 
	
				state_table_insert(state_table[UDP], (void*)&A, UDP); // UDP state
				packet_inject(fwall->pcap_in, packet, header->caplen,"IN/UDP");		
				return;
			} else if (protocol == 1) {   // ICMP
				icmp_stats A;
				icmp_stats A_inv;
				void* table_entry;
				
				NAT_ICMP(fwall, ethernet_header, ip_header, IN);
				
				ip.src_ip = unpack_4byte(ip_header->src_ip);
				ip.dst_ip = unpack_4byte(ip_header->dst_ip);
				inv_ip.src_ip = ip.dst_ip;
				inv_ip.dst_ip = ip.src_ip;
				A.ip = ip;
				A_inv.ip = inv_ip;
				A.event_time = current_time;
				A_inv.event_time = current_time;
				
				table_entry = state_table_find(state_table[ICMP], (void*)&A_inv, ICMP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, ICMP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/ICMP");			
					return;	
				}
				
				table_entry = state_table_find(state_table[ICMP], (void*)&A, ICMP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, ICMP);
					packet_inject(fwall->pcap_in, packet, header->caplen,"IN/ICMP");	
					return;		
				}
				
				if (!check_rule(IN, ICMP, ip.src_ip, ip.dst_ip, 0, 0)) // Blocked by firewall, drop the packet.
					return; 
				
				state_table_insert(state_table[ICMP], (void*)&A, ICMP); // ICMP state
				
				packet_inject(fwall->pcap_in, packet, header->caplen,"IN/ICMP");
				return;
			} else {											// Other protocol, drop
				return;	
			}
		}		
	
	}
	
	if (ethertype == ETHERTYPE_ARP) {
		arp_hdr_t* arp_header = (arp_hdr_t*)ethernet_header->data;
		uint16_t arp_operation = unpack_2byte(arp_header->operation);
		
		if (arp_operation == 1) {			  // ARP Request
			if (address_equal_ip(fwall->firewall_ip_bin, arp_header->target_protocol_addr)) { // ARP request for firewall IP
					build_ARP_reply(fwall, arp_header);
					packet_inject(fwall->pcap_out, packet, header->caplen,"OUT/ARP");
					return;
			}
		}
	}
	
}

int main(int argc, char **argv) {   
  int i;  
  char errbuf[PCAP_ERRBUF_SIZE];  
    
	if (argc < 3 || argc > 3) { // Need to handle pcap file
		printf("Usage: %s interface_in/pcap_in interface_out/pcap_out\n\n",argv[0]);
		printf("List of available interfaces:\n");
		pcap_if_t *dev_list;
		if (pcap_findalldevs(&dev_list, errbuf)==-1){
				printf("%s\n",errbuf);
		    exit(1);
		}
		
		pcap_if_t *dev_it;
		for (dev_it = dev_list; dev_it != NULL; dev_it = dev_it->next){
			printf("%s\n",dev_it->name);	
		}
		return 1;
	}
	
	firewall_t* fwall = (firewall_t*) malloc (sizeof(firewall_t));

	if (!setup_firewall(fwall, argv[1], argv[2], errbuf)) {
		printf("Error on firewall setup!\n");
		return 1;
	}
	
	if (!setup_rules(fwall)) {
		printf("Error on rules setup!\n");
		return 1;
	}

	while(1) {
		listen_in(fwall);
		listen_out(fwall);
	}	
	
  return 0;
}
