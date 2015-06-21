#include <netinet/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "headers.h"
#include "network.h"

uint16_t unpack_2byte(const uint8_t* buf) {
  uint16_t aux;
  memcpy(&aux, buf, sizeof(uint16_t));
	return ntohs(aux);
}

uint32_t unpack_4byte(const uint8_t* buf) {
  uint32_t aux;
  memcpy(&aux, buf, sizeof(uint32_t));
	return ntohl(aux);
}

uint16_t pack_2byte(uint8_t* buf) {
  uint16_t aux;
  memcpy(&aux, buf, sizeof(uint16_t));
	return htons(aux);
}

uint32_t pack_4byte(uint8_t* buf) {
  uint32_t aux;
  memcpy(&aux, buf, sizeof(uint32_t));
	return htonl(aux);
}

arp_hdr_t* arp_header_copy(arp_hdr_t* arp_header){
	arp_hdr_t* ret = (arp_hdr_t*) malloc(sizeof(arp_hdr_t));
	memcpy(ret, arp_header, sizeof(arp_hdr_t));
	return ret;
}

void compute_ip_checksum(ip_hdr_t* ip){
    ip->checksum[0] = 0;
    ip->checksum[1] = 0;
		uint8_t *data = (uint8_t*)ip;
    uint32_t acc = 0xFFFF;
		uint8_t len = ip->version_ihl;
		len = len & 0xF;
		len *= 4;
    int i;
    for (i=0;i+1<len;i+=2) {
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    if (len&1) {
        uint16_t word=0;
        memcpy(&word, ip+len-1, 1);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    uint16_t checksum = htons(~acc);
    uint8_t ax[2];
		ax[0] = (uint8_t) checksum & 0xFF;
		ax[1] = (uint8_t) (checksum>>8) & 0xFF;
		memcpy(ip->checksum,ax,sizeof(ax));
}

void compute_tcp_checksum(pseudo_tcp_hdr_t* pseudo_tcp){
    pseudo_tcp->tcp_header->checksum[0] = 0;
    pseudo_tcp->tcp_header->checksum[1] = 0;
    
		uint8_t *data = (uint8_t*)pseudo_tcp;
    uint32_t acc = 0xFFFF;
		uint16_t len = unpack_2byte(pseudo_tcp->tcp_len);
    int i;
    // Pseudo header part
    for (i=0;i+1<12;i+=2) {
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }

    // TCP header part
    data = (uint8_t*)pseudo_tcp->tcp_header;
    for (i=0;i+1<len;i+=2) {
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }

    if (len&1) {
        uint16_t word=0;
        memcpy(&word, pseudo_tcp->tcp_header->src_port+len-1, 1);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
        word=0;
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    uint16_t checksum = htons(~acc);
    uint8_t ax[2];
		ax[0] = (uint8_t) checksum & 0xFF;
		ax[1] = (uint8_t) (checksum>>8) & 0xFF;
		memcpy(pseudo_tcp->tcp_header->checksum,ax,sizeof(ax));
}

void compute_udp_checksum(pseudo_udp_hdr_t* pseudo_udp){
    pseudo_udp->udp_header->checksum[0] = 0;
    pseudo_udp->udp_header->checksum[1] = 0;
    
		uint8_t *data = (uint8_t*)pseudo_udp;
    uint32_t acc = 0xFFFF;
		uint16_t len = unpack_2byte(pseudo_udp->udp_len);

    int i;
    // Pseudo header part
    for (i=0;i+1<12;i+=2) {
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    // UDP header part
    data = (uint8_t*)pseudo_udp->udp_header;
    for (i=0;i+1<len;i+=2) {
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    if (len&1) {
        uint16_t word=0;
        memcpy(&word, pseudo_udp->udp_header->src_port+len-1, 1);
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
        word=0;
        acc += ntohs(word);
        if (acc>0xffff) acc-=0xffff;
    }
    uint16_t checksum = htons(~acc);
    uint8_t ax[2];
		ax[0] = (uint8_t) checksum & 0xFF;
		ax[1] = (uint8_t) (checksum>>8) & 0xFF;
		memcpy(pseudo_udp->udp_header->checksum,ax,sizeof(ax));
}

int hextoint(char c) {
  c = toupper(c);
  return (c > '9' ? c - 'A' + 10 : c - '0');
}

void str_to_mac(char* c, uint8_t* mac) {
  uint8_t aux;
  for (; *c; c+=3, mac++) {
    aux = (hextoint(*c) << 4) + hextoint(*(c+1));
    *mac = aux;
  }	
}

void str_to_ip(char* buf, uint8_t* ip) {
	int a, b, c, d;
	sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d);
	ip[0] = a;
	ip[1] = b;
	ip[2] = c;
	ip[3] = d;
}

void ip_to_str(uint8_t* ip, char* str){
	inet_ntop(AF_INET, ip, str, INET_ADDRSTRLEN);
}

int address_equal_str(const uint8_t *a, const uint8_t *b) {
	int i;
	int t = strlen(a);
	for (i=0;i<t;i++) if (a[i]!=b[i]) return 0;
	return 1;
}

int address_equal_ip(const uint8_t *a, const uint8_t *b) {
	int i;
	for (i=0;i<IP_SIZE;i++) if (a[i]!=b[i]) return 0;
	return 1;
}

int address_equal_mac(const uint8_t *a, const uint8_t *b) {
	int i;
	for (i=0;i<MAC_SIZE;i++) if (a[i]!=b[i]) return 0;
	return 1;
}

void mac_to_string(const uint8_t *p, char* buf) {
	int i = ETHER_ADDR_LEN; int j = 0;
  do{
    sprintf(&buf[j],"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*p++);
    j+=3;
  }while(--i>0);
  buf[j] = 0;
}

int match_name(char *a, char *b){
	int t1,t2;
	t1 = strlen(a); t2 = strlen(b);
	if (t1!=t2) return 0;
	int i;
	for (i=0;i<t1;i++)
		if (a[i]!=b[i]) return 0;
	return 1;
}

void packet_inject(pcap_t *p, const void *packet, size_t len, char* dir){
	if (ONLINE) {
		if (pcap_inject(p, packet, len) == -1) {
			printf("Error inject %s / %s\n",pcap_geterr(p), dir);
			exit(1);
		}					
	}
}

// Hash a tuple of (IP source, Port source, IP dest, Port dest)	
int hash_ip_port(ip_port_tuple ip_port) {
	int result = 17;
	result = 31 * result + ip_port.src_ip;
	result = 31 * result + ip_port.src_port;
	result = 31 * result + ip_port.dst_ip;
	result = 31 * result + ip_port.dst_port;
	if (result < 0) result *= -1;
	return result % TABLE_SIZE;
}

// Hash a tuple of (IP source, IP dest, service)
int hash_ip(ip_tuple ip) {
	int result = 17;
	result = 31 * result + ip.src_ip;
	result = 31 * result + ip.dst_ip;
	if (result < 0) result *= -1;
	return result % TABLE_SIZE;
}

int state_hash(void* stats_A, int serv_number) {
	if (serv_number == 0) {        // TCP
		tcp_stats* tcp_A = (tcp_stats*) stats_A;	
		return hash_ip_port(tcp_A->ip_port);	
	} else if (serv_number == 1) { // UDP
		udp_stats* udp_A = (udp_stats*) stats_A;	
		return hash_ip_port(udp_A->ip_port);
	} else if (serv_number == 2) { // ICMP
		icmp_stats* icmp_A = (icmp_stats*) stats_A;	
		return hash_ip(icmp_A->ip);
	}	
	printf("Invalid Service Number!\n");
	return 0;
}

int ip_port_tuple_isEqual(ip_port_tuple A, ip_port_tuple B) {
	if (A.src_ip == B.src_ip && A.src_port == B.src_port && A.dst_ip == B.dst_ip && A.dst_port == B.dst_port)
		return 1;
	return 0;
}

int ip_tuple_isEqual(ip_tuple A, ip_tuple B) {
	if (A.src_ip == B.src_ip && A.dst_ip == B.dst_ip)
		return 1;
	return 0;
}

int TCP_check_state(tcp_stats* connection, tcp_stats* A, uint8_t flags, int inv) {
	int FIN = flags & 1;
	int SYN = flags & (1 << 1);
	int RST = flags & (1 << 2);
	int PSH = flags & (1 << 3);
	int ACK = flags & (1 << 4);
	int URG = flags & (1 << 5);
	
	if (connection == NULL) { // New connection
		if (RST || FIN || ACK || PSH || !SYN)
			return 0;	
		A->last_state = 0; // New state, sent SYN
		A->fin_A = 0;
		A->fin_B = 0;	
	} else if (inv == 0) { 
	
		// A -> B packet
		if (connection->last_state == 0) { 				// Sent SYN 
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				A->last_state = 0; // Resend SYN
			} else if (ACK && !FIN) {
				return 0;
			} else if (FIN) {
				return 0;
			} else if (RST) {
				A->last_state = 4;	// Close connection
			}	
		} else if (connection->last_state == 1) { // Received SYNACK
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				return 0;
			} else if (ACK && !FIN) {
				A->last_state = 2;	// Send final 3-way handshake ACK
			} else if (FIN) {
				return 0;
			} else if (RST) {
				A->last_state = 4; // Close Connection
			}	
		} else if (connection->last_state == 2) { // Sent ACK
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				return 0;
			} else if (ACK && !FIN) {
				A->last_state = 2;	// Send data ACK.
			} else if (FIN) {
				A->last_state = 3; // Start FIN
				A->fin_A = 1;
				A->fin_B = 0;
			} else if (RST) {
				A->last_state = 4; // Close Connection
			}
		} else if (connection->last_state == 3) { // FIN seen.
			if (A->fin_A) { // Issued by A
				if (SYN && ACK) {
					return 0;
				} else if (SYN) {
					return 0;
				} else if (ACK && !FIN) {
					A->last_state = 2;	// Send ACK for B data.
				} else if (FIN) {
					A->last_state = 3; // Resend FIN
				} else if (RST) {
					A->last_state = 4; // Close Connection
				}
			} else {
				if (SYN && ACK) {
					return 0;
				} else if (SYN) {
					return 0;
				} else if (ACK && !FIN) {
					A->last_state = 2;	// Send Data
				} else if (FIN) {
					A->last_state = 4; // Send FIN and close
				} else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
		} else if (connection->last_state == 4) { // Closed connection.
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				A->last_state = 0;   // Start new connection
				A->fin_A = 0;
				A->fin_B = 0;
			} else if (ACK && !FIN) {
				return 0;
			} else if (FIN) {
				return 0;
			} else if (RST) {
				return 0;
			}
		}
	} else { 
	
		// B -> A packet
		if (connection->last_state == 0) { 				// Received SYN 
			if (SYN && ACK) {
				A->last_state = 1; // Send SYNACK
			} else if (SYN) {
				return 0;
			} else if (ACK && !FIN) {
				return 0;
			} else if (FIN) {
				return 0;
			} else if (RST) {
				A->last_state = 4;	// Close connection
			}	
		} else if (connection->last_state == 1) { // Sent SYNACK
			if (SYN && ACK) {
				A->last_state = 1; // Resend SYNACK
			} else if (SYN) {
				return 0;
			} else if (ACK && !FIN) {
				return 0;
			} else if (FIN) {
				return 0;
			} else if (RST) {
				A->last_state = 4; // Close Connection
			}	
		} else if (connection->last_state == 2) { // Received ACK
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				return 0;
			} else if (ACK && !FIN) {
				A->last_state = 2;	// Send data ACK.
			} else if (FIN) {
				A->last_state = 3; // Start FIN
				A->fin_A = 0;
				A->fin_B = 1;
			} else if (RST) {
				A->last_state = 4; // Close Connection
			}
		} else if (connection->last_state == 3) { // FIN seen.
			if (A->fin_B) { // Issued by B
				if (SYN && ACK) {
					return 0;
				} else if (SYN) {
					return 0;
				} else if (ACK && !FIN) {
					A->last_state = 2;	// Send ACK for A data.
				} else if (FIN) {
					A->last_state = 3; // Resend FIN
				} else if (RST) {
					A->last_state = 4; // Close Connection
				}
			} else {
				if (SYN && ACK) {
					return 0;
				} else if (SYN) {
					return 0;
				} else if (ACK && !FIN) {
					A->last_state = 2;	// Send Data
				} else if (FIN) {
					A->last_state = 4; // Send FIN and close
				} else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
		} else if (connection->last_state == 4) { // Closed connection.
			if (SYN && ACK) {
				return 0;
			} else if (SYN) {
				return 0;       // B can't restart connection.
			} else if (ACK && !FIN) {
				return 0;
			} else if (FIN) {
				return 0;
			} else if (RST) {
				return 0;
			}
		}
	}
	
	#ifdef DEBUGGING
		int a = A -> last_state;
		if (a==0) printf("SYN\n");
		if (a==1) printf("SYNACK\n");
		if (a==2) printf("ACK\n");
		if (a==3) printf("FIN\n");
		if (a==4) printf("CLOSED\n");
	#endif
	
	return 1;
}

int out_dated_entry(void* stats_A, void* stats_B, int serv_number) {
	struct timeval dif;
	if (serv_number == 0) { // TCP
	  tcp_stats* tcp_A = (tcp_stats*) stats_A;
		tcp_stats* tcp_B = (tcp_stats*) stats_B;
		timersub(&tcp_A->event_time, &tcp_B->event_time, &dif);	
		uint64_t milliseconds = (dif.tv_sec * (uint64_t)1000) + (dif.tv_usec / 1000);
		if (milliseconds > 60000 && tcp_B->last_state == 4) // 1 minute and closed
			return 1;
	} else if (serv_number == 1) { // UDP 
	  udp_stats* udp_A = (udp_stats*) stats_A;
		udp_stats* udp_B = (udp_stats*) stats_B;
		timersub(&udp_A->event_time, &udp_B->event_time, &dif);	
		uint64_t milliseconds = (dif.tv_sec * (uint64_t)1000) + (dif.tv_usec / 1000);
		if (milliseconds > 60000) // 1 minute
			return 1;
	} else if (serv_number == 2) { // ICMP
		icmp_stats* icmp_A = (icmp_stats*) stats_A;
		icmp_stats* icmp_B = (icmp_stats*) stats_B;
		timersub(&icmp_A->event_time, &icmp_B->event_time, &dif);	
		uint64_t milliseconds = (dif.tv_sec * (uint64_t)1000) + (dif.tv_usec / 1000);
		if (milliseconds > 60000) // 1 minute
			return 1;
	}
	return 0;
}

int match_stats(void* stats_A, void* stats_B, int type) {
	if (type == 0) { // TCP
		tcp_stats* tcp_A = (tcp_stats*) stats_A;
		tcp_stats* tcp_B = (tcp_stats*) stats_B;	
		return ip_port_tuple_isEqual(tcp_A->ip_port, tcp_B->ip_port);
	} else if (type == 1) { // UDP
		udp_stats* udp_A = (udp_stats*) stats_A;
		udp_stats* udp_B = (udp_stats*) stats_B;	
		return ip_port_tuple_isEqual(udp_A->ip_port, udp_B->ip_port);
	} else if (type == 2) { //ICMP
		icmp_stats* icmp_A = (icmp_stats*) stats_A;
		icmp_stats* icmp_B = (icmp_stats*) stats_B;
		return ip_tuple_isEqual(icmp_A->ip, icmp_B->ip);
	}
}

/******** State Table Functions ***********/

void state_table_update(void* table_entry, void* stats_A, int serv_number){
	if (serv_number == 0) {
		tcp_stats* tcp_A = (tcp_stats*) stats_A;
		tcp_stats* ptr = (tcp_stats*) table_entry;
		ptr->event_time = tcp_A->event_time;
		ptr->last_state = tcp_A->last_state;
		ptr->fin_A = tcp_A->fin_A;
		ptr->fin_B = tcp_A->fin_B;
	}	else if (serv_number == 1) {
		udp_stats* udp_A = (udp_stats*) stats_A;
		udp_stats* ptr = (udp_stats*) table_entry;
		ptr->event_time = udp_A->event_time;
	}	else if (serv_number == 2) {
		icmp_stats* icmp_A = (icmp_stats*) stats_A;
		icmp_stats* ptr = (icmp_stats*) table_entry;
		ptr->event_time = icmp_A->event_time;
	}		
}

void* state_table_find(hash_node* hash_table, void* stats_A, int serv_number) {
	int hash = state_hash(stats_A, serv_number);
	int len = hash_table[hash].len;
	if (len == 0) return NULL;
	hash_elem* ptr = hash_table[hash].head;
	hash_elem* prev = NULL; 
	while (ptr != NULL) {
		if (out_dated_entry(stats_A, ptr->stats, serv_number)){
			//Remove this entry, update
			if (prev == NULL){
				hash_table[hash].head = ptr->next;
			} else {
				prev->next = ptr->next;
			}
			hash_table[hash].len--;
			free(ptr->stats);
			free(ptr);
			if (prev == NULL)
				ptr = hash_table[hash].head;
			else
				ptr = prev;
			if (ptr == NULL)
				return NULL;
		} else {
			if (match_stats(stats_A, ptr->stats, serv_number))
				return ptr->stats;
		}
		ptr = (hash_elem*) ptr->next;
	}
	return NULL;
}


void state_table_insert(hash_node* hash_table, void* stats_A, int serv_number) {
	int hash = state_hash(stats_A, serv_number);
	hash_elem* new_node = (hash_elem*) malloc(sizeof(hash_elem));
	if (new_node == NULL) {
		printf("malloc new node fail!\n");
		return;
	}
	
	if (serv_number == 0) {
		tcp_stats* tcp_A = (tcp_stats*) stats_A;
		tcp_stats* new_tcp = (tcp_stats*) malloc(sizeof(tcp_stats));
		new_tcp->ip_port = tcp_A->ip_port;
		new_tcp->last_state = tcp_A->last_state;
		new_tcp->event_time = tcp_A->event_time;
		new_tcp->fin_A = tcp_A->fin_A;
		new_tcp->fin_B = tcp_A->fin_B;
		new_node->stats = new_tcp;
	} else if (serv_number == 1) {
		udp_stats* udp_A = (udp_stats*) stats_A;
		udp_stats* new_udp = (udp_stats*) malloc(sizeof(udp_stats));
		new_udp->ip_port = udp_A->ip_port;
		new_udp->event_time = udp_A->event_time;
		new_node->stats = new_udp;
	}else if (serv_number == 2) {
		icmp_stats* icmp_A = (icmp_stats*) stats_A;
		icmp_stats* new_icmp = (icmp_stats*) malloc(sizeof(icmp_stats));
		new_icmp->ip = icmp_A->ip;
		new_icmp->event_time = icmp_A->event_time;
		new_node->stats = new_icmp;
	}
	
	new_node->next = hash_table[hash].head;
	hash_table[hash].head = new_node;
	hash_table[hash].len++;
	return;
}

/******** Rule List Functions ***********/

void insert_rule(rule_elem* rule){
	if (rules_table.len == 0) {
		rules_table.len = 1;
		rules_table.head = rule;
		rules_table.tail = rule;
		rule->next = NULL;
		return;
	}
	rule->next = NULL;
	rules_table.tail->next = rule;
	rules_table.tail = rule;
	rules_table.len++;
	return;
}

int check_rule(int dir, int service, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
	int ret;	
	if (dir == IN) ret = 0; // Inbound is blocked
	if (dir == OUT) ret = 1; // Outbound is allowed
	
	rule_elem* ptr;
	ptr = rules_table.head;
	while(ptr != NULL) {
		if (service == TCP || service == UDP) {
			if (ptr->dir == dir) {
				if (ptr->rule == ALLOW) {
					if ((ptr->service == service || ptr->service == ANY) && 
							(ptr->src_ip == src_ip || ptr->src_ip_any) && (ptr->dst_ip == dst_ip || ptr->dst_ip_any) &&
							(ptr->src_port == src_port || ptr->src_port_any) && (ptr->dst_port == dst_port || ptr->dst_port_any) ) {
						ret = 1;	  
					}
				} else if (ptr->rule == BLOCK) {
					if ((ptr->service == service || ptr->service == ANY) && 
							(ptr->src_ip == src_ip || ptr->src_ip_any) && (ptr->dst_ip == dst_ip || ptr->dst_ip_any) &&
							(ptr->src_port == src_port || ptr->src_port_any) && (ptr->dst_port == dst_port || ptr->dst_port_any) ) {
						ret = 0;	  
					}
				}
			}	
		} else if (service == ICMP) {
			if (ptr->dir == dir) {
				if (ptr->rule == ALLOW) {
					if ((ptr->service == service || ptr->service == ANY) && 
							(ptr->src_ip == src_ip || ptr->src_ip_any) && (ptr->dst_ip == dst_ip || ptr->dst_ip_any) ) {
						ret = 1;	  
					}
				} else if (ptr->rule == BLOCK) {
					if ((ptr->service == service || ptr->service == ANY) && 
							(ptr->src_ip == src_ip || ptr->src_ip_any) && (ptr->dst_ip == dst_ip || ptr->dst_ip_any) ) {
						ret = 0;	  
					}
				}
			}
		}
		ptr = ptr->next;
	}
	return ret;	
}

int service_map(char* s){
	if (match_name(s, "tcp"))  return 0;
	if (match_name(s, "udp"))  return 1;
	if (match_name(s, "icmp")) return 2;
	if (match_name(s, "any"))  return 3;
	return -1;
}

/***********************************/



/* DEBUG FUNCTIONS */
#define HEX_IP 18

void print_mac(char * str){
	int i;
	for (i=0;i<HEX_IP;i++)
		printf("%c",str[i]);
}

void print_ip(char * str){
	int i;
	int t = strlen(str);
	for (i=0;i<t;i++)
		printf("%c",str[i]);
}

void print_ethernet(ethernet_hdr_t* ethernet_header, char* dir){
	char str[64];
	char arp[] = "ARP";
	char ip[] = "IP";
	char null[] = "null";
	char *type = null;
	uint16_t ethertype = unpack_2byte(ethernet_header->ethertype);
	if (ethertype == ETHERTYPE_ARP) type = arp;
	if (ethertype == ETHERTYPE_IP) type = ip;
	
	
	mac_to_string(ethernet_header->src_mac, str);
	printf("Packet %s (%s): ",dir, type);
	print_mac(str);
	printf(" -> ");
	mac_to_string(ethernet_header->dst_mac, str);
	print_mac(str);
	printf("\n");
}

void print_ip_packet(ip_hdr_t* ip_header, char* dir){
	char str[64];
	inet_ntop(AF_INET, ip_header->src_ip, str, INET_ADDRSTRLEN);
	printf("  # IP %s: ", dir);
	print_ip(str);
	printf(" to ");
	inet_ntop(AF_INET, ip_header->dst_ip, str, INET_ADDRSTRLEN);
	print_ip(str);
	printf("\n");
}
