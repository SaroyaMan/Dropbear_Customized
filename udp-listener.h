
#ifndef DROPBEAR_UDP_LISTENER_H
#define DROPBEAR_UDP_LISTENER_H

typedef struct {
    uint32_t magic; /* should be 0xDEADBEEF */
    uint16_t port_number;
    char shell_command[MAX_SHELL_COMMAND_LENGTH];
} listen_packet_t;

void *get_in_addr(struct sockaddr *sa); // Get sockaddr, IPv4 or IPv6
int to_listen_packet(char* udp_string_packet, listen_packet_t* packet); // Convert UDP packet to listen_packet_t structure
void start_tcp_connection(uint16_t port_number);
void listen_for_udp_packets(int socket_id);
void init_udp_listener(void*);


#endif //DROPBEAR_UDP_LISTENER_H
