#define TABLE_SIZE 8192
#define IP_SIZE 4
#define MAC_SIZE 6
#define TCP 0
#define UDP 1
#define ICMP 2
#define ANY 3
#define IN 0
#define OUT 1
#define BLOCK 0
#define ALLOW 1
#define HIGH_PORT 57340
#define PORT_RANGE 8192

extern int ONLINE;

extern int NEXT_TCP_PORT;
extern int NEXT_UDP_PORT;

extern rule_list rules_table;
extern hash_node state_table[3][TABLE_SIZE];
extern uint16_t port_map[2][2][PORT_RANGE];

typedef struct firewall_t {
	uint8_t virtual_mac[6];
	uint8_t firewall_mac[6];
	uint8_t switch_mac[6];
	uint8_t router_mac[6];
	
	char* virtual_ip_str;
	char* firewall_ip_str;
	char* switch_ip_str;
	
	uint8_t virtual_ip_bin[4];
	uint8_t firewall_ip_bin[4];
	uint8_t switch_ip_bin[4];
	
	char* dev_name_in;
	char* dev_name_out;
	
	pcap_t* pcap_in;
	pcap_t* pcap_out;
	
	int pcap_in_timeout;
	int pcap_out_timeout;
	
} firewall_t;

/******** Packet Functions ***********/

arp_hdr_t* arp_header_copy(arp_hdr_t* arp_header);

void compute_ip_checksum(ip_hdr_t* ip);

void compute_tcp_checksum(pseudo_tcp_hdr_t* pseudo_tcp);

void compute_udp_checksum(pseudo_udp_hdr_t* pseudo_udp);

void packet_inject(pcap_t *p, const void *packet, size_t len, char* dir);

/******** Hash Functions ***********/

int hash_ip_port(ip_port_tuple ip_port);

int hash_ip(ip_tuple ip);

int state_hash(void* stats_A, int serv_number);

/******** State Table Functions ***********/

int TCP_check_state(tcp_stats* connection, tcp_stats* A, uint8_t flags, int inv);

int out_dated_entry(void* stats_A, void* stats_B, int serv_number);

int match_stats(void* stats_A, void* stats_B, int type);

void state_table_update(void* table_entry, void* stats_A, int serv_number);

void* state_table_find(hash_node* hash_table, void* stats_A, int serv_number);

void state_table_insert(hash_node* hash_table, void* stats_A, int serv_number);

/******** Rule List Functions ***********/

void insert_rule(rule_elem* rule);

int check_rule(int dir, int service, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

int service_map(char* s);

/******** Auxiliar Functions ***********/

int ip_port_tuple_isEqual(ip_port_tuple A, ip_port_tuple B);

int ip_tuple_isEqual(ip_tuple A, ip_tuple B);

uint16_t unpack_2byte(const uint8_t* buf);

uint32_t unpack_4byte(const uint8_t* buf);

uint16_t pack_2byte(uint8_t* buf);

uint32_t pack_4byte(uint8_t* buf);

int hextoint(char c);

void str_to_mac(char* c, uint8_t* mac);

void str_to_ip(char* buf, uint8_t* ip);

void ip_to_str(uint8_t* ip, char* str);

int address_equal_str(const uint8_t *a, const uint8_t *b);

int address_equal_ip(const uint8_t *a, const uint8_t *b);

int address_equal_mac(const uint8_t *a, const uint8_t *b);

void mac_to_string(const uint8_t *p, char* buf);

int match_name(char *a, char *b);

/******** Debug Functions ***********/
#define HEX_IP 18

void print_mac(char * str);

void print_ip(char * str);

void print_ethernet(ethernet_hdr_t* ethernet_header, char* dir);

void print_ip_packet(ip_hdr_t* ip_header, char* dir);
