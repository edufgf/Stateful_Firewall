/******** Header structs ***********/

typedef struct ethernet_hdr_t {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint8_t ethertype[2];
  uint8_t data[0];
} ethernet_hdr_t;

typedef struct ip_hdr_t {
  uint8_t version_ihl;
  uint8_t dscp_ecn;
  uint8_t total_len[2];
  uint8_t identification[2];
  uint8_t flags_frag_offset[2];
  uint8_t ttl;
  uint8_t protocol;
  uint8_t checksum[2];
  uint8_t src_ip[4];
  uint8_t dst_ip[4];
  uint8_t options_and_data[0];
} ip_hdr_t;

typedef struct tcp_hdr_t {
  uint8_t src_port[2];
  uint8_t dst_port[2];
	uint8_t seq_number[4];
	uint8_t ack_number[4];
	uint8_t offset_reserved_flag;
	uint8_t flags;
	uint8_t window_size[2];
	uint8_t checksum[2];
	uint8_t urg_pointer[2];
  uint8_t options_and_data[0];
} tcp_hdr_t;

typedef struct pseudo_tcp_hdr_t {
	uint8_t src_ip[4];
  uint8_t dst_ip[4];
  uint8_t reserved;
  uint8_t protocol;
  uint8_t tcp_len[2];
	tcp_hdr_t* tcp_header;
} pseudo_tcp_hdr_t;

typedef struct udp_hdr_t {
  uint8_t src_port[2];
  uint8_t dst_port[2];
	uint8_t len[2];
	uint8_t checksum[2];
  uint8_t data[0];
} udp_hdr_t;

typedef struct pseudo_udp_hdr_t {
	uint8_t src_ip[4];
  uint8_t dst_ip[4];
  uint8_t reserved;
  uint8_t protocol;
  uint8_t udp_len[2];
	udp_hdr_t* udp_header;
} pseudo_udp_hdr_t;

typedef struct icmp_hdr_t {
  uint8_t type;
  uint8_t code;
  uint8_t checksum[2];
  uint8_t remainder[4];
} icmp_hdr_t;

typedef struct arp_hdr_t {
  uint8_t datalink_type[2];
  uint8_t protocol_type[2];
	uint8_t hardware_len;
	uint8_t protocol_len;
	uint8_t operation[2];
  uint8_t sender_hardware_addr[6];
  uint8_t sender_protocol_addr[4];
  uint8_t target_hardware_addr[6];
  uint8_t target_protocol_addr[4];
} arp_hdr_t;

/***********************************/
// IP block rules work on network byte order. (maybe not)

typedef struct ip_port_tuple {
	uint32_t src_ip, dst_ip;
	uint16_t src_port, dst_port;
} ip_port_tuple;

typedef struct ip_tuple {
  uint32_t src_ip, dst_ip;
} ip_tuple;

typedef struct ip_stats {
	ip_tuple ip;  
	int service;
} ip_stats;

typedef struct tcp_stats {
	ip_port_tuple ip_port;
  int last_state;
  int fin_A, fin_B; 
	// Who sent FIN (A -> B)    
  struct timeval event_time;
	//0 SYN (A->B)
	//1 SYN ACK(B->A) half-open
	//2 ACK (A->B) complete handshake
	//3 FIN initiated
  //4 Closed Connection (by FIN or RST)
} tcp_stats;

typedef struct udp_stats {
	ip_port_tuple ip_port;  
	struct timeval event_time;
} udp_stats;

typedef struct icmp_stats {
	ip_tuple ip;  
	struct timeval event_time;
} icmp_stats;

typedef struct hash_elem {
  void *stats;
	void *next;
} hash_elem;

typedef struct hash_node {
  int len;
	hash_elem* head;
} hash_node;

typedef struct rule_elem {
	int rule, dir, service;
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  uint8_t src_ip_any, dst_ip_any;
  uint8_t src_port_any, dst_port_any;
	void *next;
} rule_elem;

typedef struct rule_list {
  int len;
	rule_elem* head;
	rule_elem* tail;
} rule_list;


