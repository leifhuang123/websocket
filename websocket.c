#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "websocket.h"

#define BUFFER_SIZE 1024
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/*-------------------------------------------------------------------
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
--------------------------------------------------------------------*/
typedef struct 
{
    /* byte 0 */
    uint8_t opcode:4; 
    uint8_t r:3;
    uint8_t fin:1;  

    /* byte 1 */
    uint8_t payload_len:7; 
    uint8_t mask:1;
    
    union {
        uint16_t short_len; // if (payload_len == 126) 
        uint64_t long_len; // if (payload_len == 127) 
    }payload_len_ext;
    
    uint8_t masking_key[4]; //if (mask ==1 )
}frame_head;

static char rx_buffer[BUFFER_SIZE];
static char tx_buffer[BUFFER_SIZE];

static int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length-1] = '\0';
    size = bptr->length;

    BIO_free_all(bio);
    return size;
}


static int read_line(char* allbuf, int level, char* linebuf)
{
    int len = strlen(allbuf);
    for (; level<len; ++level)
    {
        if(allbuf[level]=='\r' && allbuf[level+1]=='\n')
            return level+2;
        else
            *(linebuf++) = allbuf[level];
    }
    return -1;
}

int ws_shake_hands(int fd)
{
    //next line's point num
    int level = 0;
    //a line data
    char linebuf[256];
    //Sec-WebSocket-Accept
    char sec_accept[32];
    //sha1 data
    unsigned char sha1_data[SHA_DIGEST_LENGTH+1]={0};
   
    memset(rx_buffer, 0, sizeof(rx_buffer));
    memset(tx_buffer, 0, sizeof(tx_buffer));

    if (read(fd, rx_buffer, sizeof(rx_buffer)) <= 0) {
        perror("read");
        return -1;
    }
    do {
        memset(linebuf, 0, sizeof(linebuf));
        level = read_line(rx_buffer, level, linebuf);

        if (strstr(linebuf, "Sec-WebSocket-Key")!=NULL)
        {
            strcat(linebuf, GUID);
            SHA1((unsigned char*)&linebuf+19, strlen(linebuf+19), (unsigned char*)&sha1_data);
            base64_encode(sha1_data, strlen(sha1_data), sec_accept);
            /* write the response */
            sprintf(tx_buffer, "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\n" \
                          "Connection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: %s\r\n" \
                          "\r\n",sec_accept);

            if (write(fd, tx_buffer, strlen(tx_buffer)) < 0) {
                perror("write");
                return -1;
            }
            return 0;
        }
    }while((rx_buffer[level]!='\r' || rx_buffer[level+1]!='\n') && level!=-1);
    return -1;
}

static void umask(char *data, int len, char *mask)
{
    int i;
    for (i=0; i<len; ++i) {
        *(data + i) ^= *(mask + (i % 4));
    }
}

static void swap_char(char *m, char *n)
{
    if (!m || !n) return;
    char temp = *m;
    *m = *n;
    *n = temp;
}

static int parse_frame_head(const char *buffer, frame_head * head)
{
    int head_len = 0;
    frame_head *recv_head = (frame_head *)buffer; 
#ifdef DEBUG
    printf("fin=%d,opcode=%d,mask=%d,len=%d\n", recv_head->fin, recv_head->opcode, 
            recv_head->mask, recv_head->payload_len);
#endif   
    if (!recv_head->mask) {
        return -1; // refuse data without mask
    }
    memcpy(head, recv_head, 2);
    if (recv_head->payload_len < 126) {
        head_len = 2;
    }
    else if (recv_head->payload_len == 126)
    {
        char *ext_len = (char *)(buffer + 2);
        // from network big edian to little edian
        swap_char(&ext_len[0], &ext_len[1]);
        memcpy(&(head->payload_len_ext.short_len), ext_len, 2);
        head_len = 4;
    }
    else if (recv_head->payload_len == 127)
    {
        char *ext_len = (char *)(buffer + 2);
        char i;
        // from network big edian to little edian
        for(i=0; i<4; i++)
        {
            swap_char(&ext_len[i], &ext_len[7-i]);
        }
        memcpy(&(head->payload_len_ext.long_len), ext_len, 8);
        head_len = 10;
    }
    else {
        printf("payload_len error\n");
        return -1;
    }
    if (recv_head->mask == 1) {
        memcpy(head->masking_key, buffer + head_len, 4);
        head_len += 4;
    }
    return head_len;
}

static int ws_close_response(int fd)
{
    char tx_buffer[2];
    tx_buffer[0] = WS_OP_CLOSE;
    tx_buffer[1] = 0;
    return write(fd, tx_buffer, 2);
}

static int pack_frame(const char * payload, int payload_len)
{
    memset(tx_buffer, 0, sizeof(tx_buffer));
    
    if (payload_len < 126)
    {
        tx_buffer[0] = 0x81;
        tx_buffer[1] = payload_len;
        memcpy(tx_buffer+2, payload, payload_len);
        return payload_len + 2;
    }
    else if (payload_len < 0xFFFF)
    {
        tx_buffer[0] = 0x81;
        tx_buffer[1] = 126;
        tx_buffer[2] = (payload_len>>8 & 0xFF);
        tx_buffer[3] = (payload_len & 0xFF);
        memcpy(tx_buffer+4, payload, payload_len);    
        return payload_len + 4;
    }
    else
    {
        return 0;// no support now
    }
}

int ws_recv_frame(int fd, char **payload)
{
    frame_head head;
    int recv_len, head_len, payload_len;
    memset(&head, 0, sizeof(head));
    memset(rx_buffer, 0, sizeof(rx_buffer));
    
    recv_len = read(fd, rx_buffer, BUFFER_SIZE);
    if (recv_len < 2) {
        printf("ws recv_len(%d)<2\n", recv_len);
        return -1;
    }
    head_len = parse_frame_head(rx_buffer, &head);
    switch (head.opcode)
    {
    case WS_OP_CLOSE: {
        ws_close_response(fd);
        return -1; // close the socket
    }
    case WS_OP_STRING: 
    case WS_OP_BINARY:
    {
        payload_len = recv_len - head_len;
        /* check payload_len */
        if (((head_len == 6) && (payload_len == head.payload_len)) ||
            ((head_len == 8) && (payload_len == head.payload_len_ext.short_len)) ||
            ((head_len == 14) && (payload_len == head.payload_len_ext.long_len)))
        {
            #ifdef DEBUG
            printf("head_len=%d, payload_len=%d\n", head_len, payload_len);
            #endif
            *payload = rx_buffer + head_len;
            //umask payload data
            umask(*payload, payload_len, head.masking_key);
            return payload_len;
        }
    }
    default:
        break;
    }
    return 0;
}

int ws_send_frame(int fd, const char *payload, int payload_len)
{
    int size = pack_frame(payload, payload_len);
    if (size < 1) return -1; /* no data to send */
    
    return write(fd, tx_buffer, size);
}
