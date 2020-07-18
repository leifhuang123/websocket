#ifndef _WEBSOCKET_H
#define _WEBSOCKET_H

/* ws constants */
#define WS_OP_STREAMFRAME   0
#define WS_OP_STRING        1
#define WS_OP_BINARY        2
#define WS_OP_CLOSE         8
#define WS_OP_PING          9
#define WS_OP_PONG          10    

int ws_shake_hands(int fd);

int ws_recv_frame(int fd, char **payload);

int ws_send_frame(int fd, const char *payload, int payload_len);

#endif
