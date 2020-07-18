#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "websocket.h"

#define BUFFER_SIZE 1024
#define WS_TCP_PORT 4444
#define WS_CONN_MAX 30

struct ws
{
    uint64_t id;     /* client id = {remote ip address, remote port} */
    int fd;          /* ws conn socket */
    bool handshaken; /* ws conn status */
    bool connected;  /* tcp connected */
};

/* global structure that contains clients info */
static struct ws clients[WS_CONN_MAX] = {0};
static int client_cnt = 0;

static void add_client(int newfd, uint64_t id)
{
    int i, index = -1;
    if (client_cnt >= WS_CONN_MAX)
    {
        printf("client list is full!\n");
        return;
    }
    else if (clients[client_cnt].connected == false)
    {
        index = client_cnt;
    }
    else
    { /* find a valid space to store client info */
        for (i = 0; i < WS_CONN_MAX; i++)
        {
            if (clients[i].connected == false)
            {
                index = i;
                break;
            }
        }
    }
    if (index < 0 || index >= WS_CONN_MAX)
    {
        printf("add_client failed!\n");
        return;
    }
    clients[index].fd = newfd;
    clients[index].id = id;
    clients[index].handshaken = false;
    clients[index].connected = true;
    ++client_cnt;
}

static void del_client(uint64_t id)
{
    int i;
    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (id == clients[i].id)
        {
            close(clients[i].fd);
            memset(&clients[i], 0, sizeof(struct ws)); // connected = false;
            --client_cnt;
            break;
        }
    }
}

/* message :
    0. S -> C:     {"id":"%X"}
    1. C <-> S:    {"from":"ID_src","to":"ID_dst","msg":"%s"}
    2. C <-> S:    {"from":"ID_src","to":"0","msg":"%s"}
    3. S -> C:     {"friends":["0", "%X", "%X"...]}
    4. C -> S:     getFriends
*/
void print_all_clients(int fd)
{
    int i;
    char resp[BUFFER_SIZE];
    char *ptr = NULL;
    memset(resp, 0, sizeof(resp));
    sprintf(resp, "%s", "{\"friends\":[\"0\",");
    ptr = resp + strlen(resp);

    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (clients[i].connected == true)
        {
            sprintf(ptr, "\"%lX\",", clients[i].id);
            ptr = resp + strlen(resp);
        }
    }
    resp[strlen(resp) - 1] = '\0'; // remove ','
    sprintf(ptr - 1, "%s", "]}");
    ws_send_frame(fd, resp, strlen(resp));
}

void print_client_id(int fd, uint64_t id)
{
    char resp[32];
    sprintf(resp, "{\"id\":\"%lX\"}", id);
    ws_send_frame(fd, resp, strlen(resp));
}

int forward_msg(uint64_t id_dst, const char *msg, int len)
{
    int i;
    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (id_dst == clients[i].id)
        {
            printf("forward msg to id %lX\n", id_dst);
            return ws_send_frame(clients[i].fd, msg, len);
        }
    }
    printf("no destination to forward\n");
    return -1;
}

void notify_all_clients(const char *msg, int len)
{
    int i;
    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (clients[i].connected == true)
        {
            printf("notify msg to ID %lX\n", clients[i].id);
            ws_send_frame(clients[i].fd, msg, len);
        }
    }
}

void parse_ws_msg(int fd, const char *payload)
{
    char *dest = NULL;
    uint64_t id;
    char resp[64] = {0};
    int ret;

    if (!strncmp(payload, "{\"from", strlen("{\"from")))
    {
        if (!(dest = strstr(payload, "\"to\":")))
            return;
        dest += strlen("\"to\":");
        if (sscanf(dest, "\"%lX\"", &id) != 1)
            return;
        printf("to:%lX\n", id);

        if (id == 0)
        {
            // notify all clients in group 0
            notify_all_clients(payload, strlen(payload));
        }
        else
        {
            ret = forward_msg(id, payload, strlen(payload));
            if (ret < 0)
            {
                sprintf(resp, "send to ID%lX failed!\n", id);
                ws_send_frame(fd, resp, strlen(resp));
            }
        }
    }
    else if (strncmp(payload, "getFriends", strlen("getFriends")) == 0)
    {
        print_all_clients(fd);
    }
    else
    {
        ws_send_frame(fd, "Unkown Request!", strlen("Unkown Request!"));
    }
}

void ws_handler(struct ws *client)
{
    char *payload = NULL;
    int size;

    if (!client->handshaken)
    {
        if (ws_shake_hands(client->fd) == 0)
        {
            client->handshaken = true;
            print_client_id(client->fd, client->id);
        }
        return;
    }

    size = ws_recv_frame(client->fd, &payload);
    if (size < 0 || !payload)
    {
        printf("recv_frame error\n");
        del_client(client->id);
        return;
    }
    parse_ws_msg(client->fd, payload);
}

int start_tcp_server(int port)
{
    int sockfd, optval = 1;
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }
    if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) < 0)
    {
        perror("setsockopt");
        return -1;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        perror("bind");
        return -1;
    }
    // max connection: WS_CONN_MAX
    if (listen(sockfd, WS_CONN_MAX) < 0)
    {
        perror("listen");
        return -1;
    }
    return sockfd;
}

static int update_fd_set(fd_set *pfds)
{
    int i;
    int fdmax = -1;
    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (clients[i].connected)
        {
            FD_SET(clients[i].fd, pfds);
            if (clients[i].fd > fdmax)
                fdmax = clients[i].fd;
        }
    }
    return fdmax;
}

void cleanup(void)
{
    int i;
    for (i = 0; i < WS_CONN_MAX; i++)
    {
        if (clients[i].connected)
        {
            close(clients[i].fd);
        }
    }
}

int main(void)
{
    int listenfd;

    fd_set readfds; /* watch these for input */
    int maxfd;      /* max fd */
    int retval;     /* return for select */

    printf("WebSocketServer Start!\n");
    listenfd = start_tcp_server(WS_TCP_PORT);

    while (1)
    {
        /* Set sockets to watch */
        FD_ZERO(&readfds);
        FD_SET(listenfd, &readfds);
        retval = update_fd_set(&readfds);
        maxfd = (retval > listenfd) ? retval : listenfd;

        /* wait for input */
        retval = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (retval == 0)
        {
            continue;
        }
        else if (retval < 0)
        {
            perror("select");
            break;
        }
        else
        {
            if (FD_ISSET(listenfd, &readfds))
            {
                struct sockaddr_in sockaddr;
                socklen_t addrlen = sizeof(sockaddr);
                int sockfd = accept(listenfd, (struct sockaddr *)&sockaddr, &addrlen);
                if (sockfd < 0)
                {
                    perror("accept");
                    break;
                }
                uint64_t id = ((uint64_t)sockaddr.sin_addr.s_addr << 32) | sockaddr.sin_port;
                add_client(sockfd, id);
            }
            else
            {
                int i;
                for (i = 0; i < WS_CONN_MAX; i++)
                {
                    /* check bits for each fd */
                    if (FD_ISSET(clients[i].fd, &readfds))
                    {
                        ws_handler(&clients[i]);
                    }
                }
            }
        }
    }
    cleanup();
    close(listenfd);
    return 0;
}
