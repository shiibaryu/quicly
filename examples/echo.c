#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>  
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

static quicly_context_t ctx;

static quicly_cid_plaintext_t next_cid;

static int is_server(void)
{
        return ctx.tls->certificates.count != 0;
}

static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
           "Options:\n"
           "  -c <file>    specifies the certificate chain file (PEM format)\n"
           "  -k <file>    specifies the private key file (PEM format)\n"
           "  -p <number>  specifies the port number (default: 4433)\n"
           "  -E           logs events to stderr\n"
           "  -h           prints this help\n"
           "\n"
           "When both `-c` and `-k` is specified, runs as a server.  Otherwise, runs as a\n"
           "client connecting to host:port.  If omitted, host defaults to 127.0.0.1.\n",
           progname);
    exit(0);
}
static int on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    return 0;
}

static int on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    return 0;
}

static int on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    int ret;

    /* read input to receive buffer */
    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
        return ret;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (is_server()) {
        /* server: echo back to the client */
        if (quicly_sendstate_is_open(&stream->sendstate)) {
            quicly_streambuf_egress_write(stream, input.base, input.len);
            /* shutdown the stream after echoing all data */
            if (quicly_recvstate_transfer_complete(&stream->recvstate))
                quicly_streambuf_egress_shutdown(stream);
        }
    } else {
        /* client: print to stdout */
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
        /* initiate connection close after receiving all data */
        if (quicly_recvstate_transfer_complete(&stream->recvstate))
            quicly_close(stream->conn, 0, "");
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    return 0;
}

static void process_msg(int is_client, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len,int tun_fd,unsigned int host)
{
    size_t off, packet_len, i;

    /* split UDP datagram into multiple QUIC packets */
    for (off = 0; off < dgram_len; off += packet_len) {
        quicly_decoded_packet_t decoded;
        if ((packet_len = quicly_decode_packet(&ctx, &decoded,msg->msg_iov[0].iov_base + off, dgram_len - off)) == SIZE_MAX)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], msg->msg_name, msg->msg_namelen, &decoded))
                break;
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            ipoc_receive(conns[i], &decoded,tun_fd,host);
        } else if (!is_client) {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &ctx, msg->msg_name, msg->msg_namelen, &decoded, ptls_iovec_init(NULL, 0), &next_cid, NULL);
        }
    }
}


static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }
}

   

int tun_alloc(char *dev)
{
        struct ifreq ifr;
        int fd,ret;
        char *i_dev = "/dev/net/tun";
        
        if((fd = open(i_dev,O_RDWR)) <0){
                perror("failed to open tun");
                return fd;
        }
        
        memset(&ifr,0,sizeof(ifr));
        
        ifr.ifr_flags = IFF_TUN;
        
        if(*dev){
                strncpy(ifr.ifr_name,dev,IFNAMSIZ);
        }     

        ret = ioctl(fd,TUNSETIFF,(void *)&ifr);
        if(ret < 0){
                perror("ioctl(TUNSETIFF)");
                close(fd);
                return ret;
        }

        strcpy(dev,ifr.ifr_name);

        return fd;
}

static int send_one(int fd, quicly_datagram_t *p)
{
    struct iovec vec = {.iov_base = p->data.base, .iov_len = p->data.len};
    struct msghdr mess = {.msg_name = &p->sa, .msg_namelen = p->salen, .msg_iov = &vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}


static int run_ipoc(int sock_fd,int tun_fd,unsigned int host,quicly_conn_t *client)
{
        quicly_conn_t *conns[256] = {client};
        size_t i;
        int max_fd;

        while(1){
                        fd_set readfds;
                        struct timeval tv;
                do {
                        int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
                        for (i = 0; conns[i] != NULL; ++i) {
                                int64_t conn_timeout = quicly_get_first_timeout(conns[i]);
                                if (conn_timeout < first_timeout)
                                        first_timeout = conn_timeout;
                        }
                        if (now < first_timeout) {
                                int64_t delta = first_timeout - now;
                                if (delta > 1000 * 1000)
                                        delta = 1000 * 1000;
                                tv.tv_sec = delta / 1000;
                                tv.tv_usec = (delta % 1000) * 1000;
                        } else {
                                tv.tv_sec = 1000;
                                tv.tv_usec = 0;
                        }

                        max_fd = sock_fd >= tun_fd ? sock_fd : tun_fd;

                        FD_ZERO(&readfds);
                        FD_SET(sock_fd,&readfds);
                        FD_SET(tun_fd, &readfds);
                }while(select(max_fd + 1,&readfds,NULL,NULL,&tv) == -1 && errno == EINTR);
                
                /*read data from tun_fd and pack it in quic packet*/
                if(FD_ISSET(tun_fd,&readfds)){
                        uint8_t buf[1500];
                        struct msghdr mess;
                        struct sockaddr sa;
                        struct iovec vec;
                        memset(&mess, 0, sizeof(mess));
                        mess.msg_name = &sa;
                        mess.msg_namelen = sizeof(sa);
                        vec.iov_base = buf;
                        vec.iov_len = sizeof(buf);
                        mess.msg_iov = &vec;
                        mess.msg_iovlen = 1;
                        ssize_t rret;

                        while(((rret = recvmsg(tun_fd,&mess,0)) == -1 && errno == EINTR))
                                ;
                        if(rret > 0){
                                for(i=0;conns[i] != NULL;++i){
                                        quicly_datagram_t *dgrams[i];
                                        dgrams->data.base = buf;
                                        dgrams->data.len = sizeof(buf);
                                        size_t num_dgrams = 1;
                                        int ret =  quicly_send(conns[i],dgrams,&num_dgrams);
                                        switch(ret){
                                        case 0:{
                                                size_t j;
                                                for (j = 0; j != num_dgrams; ++j) {
                                                        send_one(fd, dgrams[j]);
                                                        ctx.packet_allocator->free_packet(ctx.packet_allocator, dgrams[j]);
                                                }
                                        }break;
                                        case QUICLY_ERROR_FREE_CONNECTION:
                                                quicly_free(conns[i]);
                                                memmove(conns + i,conns+i+1,sizeof(conns)-sizeof(conns[0])*(i+1));
                                                i--;
                                                if(!is_server())
                                                        return 0;
                                                break;
                                        default:
                                                fprintf(stderr,"quicly_send returned %d\n",ret);
                                                return 1;
                                        }
                                }
                        }
                }
                if(FD_ISSET(sock_fd,&readfds)){
                        uint8_t buf[1500];
                        struct msghdr mess;
                        struct sockaddr sa;
                        struct iovec vec;
                        memset(&mess, 0, sizeof(mess));
                        mess.msg_name = &sa;
                        mess.msg_namelen = sizeof(sa);
                        vec.iov_base = buf;
                        vec.iov_len = sizeof(buf);
                        mess.msg_iov = &vec;
                        mess.msg_iovlen = 1;
                        ssize_t rret;

                        while(((rret = recvmsg(sock_fd,&mess,0)) == -1 && errno == EINTR))
                                ;
                        if(rret > 0){
                                process_msg(client != NULL,conns,&mess,rret,tun_fd,host);
                        }
                        
                        for(i=0;conns[i] != NULL;++i){
                                quicly_datagram_t *dgrams[i];
                                size_t num_dgrams = 1;
                                int ret = quicly_send(conns[i],dgrams,&num_dgrams);
                                switch(ret){
                                case 0:{
                                        size_t j;
                                        for (j = 0; j != num_dgrams; ++j) {
                                                send_one(fd, dgrams[j]);
                                                ctx.packet_allocator->free_packet(ctx.packet_allocator, dgrams[j]);
                                        }
                                }break;
                                case QUICLY_ERROR_FREE_CONNECTION:
                                       quicly_free(conns[i]);
                                       memmove(conns + i,conns+i+1,sizeof(conns)-sizeof(conns[0])*(i+1));
                                       i--;
                                       if(!is_server())
                                            return 0;
                                       break;
                               default:
                                       fprintf(stderr,"quicly_send returned %d\n",ret);
                                       return 1;
                                }
                       }
                }
        }

        return 0;
}
int main(int argc,char **argv)
{
        int sock_fd,tun_fd;
        int option;
        char ifname[IFNAMSIZ] = "";
        char *host = "127.0.0.1";
        /*unsigned int host;*/
        char *port = "3000";
        struct sockaddr sa;
        socklen_t salen;
        
        ptls_openssl_sign_certificate_t sign_certificate;
        ptls_context_t tlsctx = {
                .random_bytes   = ptls_openssl_random_bytes,
                .get_time       = &ptls_get_time,
                .key_exchanges   = ptls_openssl_key_exchanges,
                .cipher_suites  = ptls_openssl_cipher_suites,
        };

        quicly_stream_open_t stream_open = {on_stream_open};

        /* setup quic context */
        ctx = quicly_spec_context;
        ctx.tls = &tlsctx;
        quicly_amend_ptls_context(ctx.tls);
        ctx.stream_open = &stream_open;
        
        while((option = getopt(argc,argv,"c:k:i:p:h:d")) != 0){
                switch(option){
                        case 'c': /* load certificate chain */ {
                                int ret;
                                if ((ret = ptls_load_certificates(&tlsctx, optarg)) != 0) {
                                        fprintf(stderr, "failed to load certificates from file %s:%d\n", optarg, ret);
                                        exit(1);
                                }
                        }break;
                        case 'k': /* load private key */ {
                                FILE *fp;
                                if ((fp = fopen(optarg, "r")) == NULL) {
                                        fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                                        exit(1);
                                }
                                EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
                                fclose(fp);
                                if (pkey == NULL) {
                                        fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                                        exit(1);
                                }
                                ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
                                EVP_PKEY_free(pkey);
                                tlsctx.sign_certificate = &sign_certificate.super;
                        }break;
                        case 'i':
                                strncpy(ifname,optarg,IFNAMSIZ-1);
                                break;
                        case 'p':
                                port = optarg;
                                break;
                        case 'd':
                                host = optarg;
                                break;
                        case 'h':
                                usage(argv[0]);
                                break;
                }
        }
        
        if((tlsctx.certificates.count != 0) != (tlsctx.sign_certificate != NULL)){
                fprintf(stderr,"-c and -k options must be used together\n");
                exit(-1);
        }

        argc -= optind;
        argv += optind;  
        
        if(argc != 0){
                host = *argv++;
        }

        if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
                exit(1);


        sock_fd = socket(sa.sa_family,SOCK_DGRAM,0);
        if(sock_fd < 0){
                perror("failed to make a socket");
        }

        tun_fd = tun_alloc(ifname);
        if(tun_fd < 0){
               printf("failed to connect tun/tap interface");
               exit(1);
        }
        
        if(is_server()){
                int reuseaddr = 1;
                setsocketopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr));
                if(bind(sock_fd,(struct sockaddr *)&sa,salen) != 0){
                        perror("failed to bind\n");
                        exit(1);
                }
        }else{
                struct sockaddr_in local;
                memset(&local,0,sizeof(local));
                if(bind(sock_fd,(struct sockaddr *)&local,sizeof(local)) != 0){
                        perror("failed to bind");
                        exit(1);
                }
        }
        quicly_conn_t *client = NULL;
        if (!is_server()) {
                /* initiate a connection, and open a stream */
                int ret;
                if ((ret = quicly_connect(&client, &ctx, host, (struct sockaddr *)&sa, salen, &next_cid, NULL, NULL)) != 0) {
                        fprintf(stderr, "quicly_connect failed:%d\n", ret);
                        exit(1);
                }
                quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
                quicly_open_stream(client, &stream, 0);
        }
        return run_ipoc(sock_fd,tun_fd,(unsigned int)host,client);
}