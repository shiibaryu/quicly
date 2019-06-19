#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <getopt.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <openssl/pem.h>
#include "tun.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

static quicly_context_t ctx;

static quicly_cid_plaintext_t next_cid;

static int address_resolver(struct sockaddr *sa,socklen_t *salen,const char *host,const char *port,int family,int type,int proto)
{
        struct addrinfo hints,*res;
        int ret;

        hints.ai_socktype = type;
        hints.ai_family   = family;
        hints.ai_protocol = protocol;
        hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
        if((ret = getaddrinfo(host,port,&hints,&res)) != 0 || res == NULL){
                fprintf(stderr,"failed to resolve address %s:%s:%s\n",host,port,
                ret != 0 ? gai_strerror(err):"getaddrinfo returned NULL");
                return -1;
        }

        memcpy(sa,res->ai_addr,res->ai_addrlen);
        *sa_len = res->ai_addrlen;

        freeaddrinfo(res);

        return 0;
}

int tun_alloc(char *dev)
{
        struct ifreq ifr;
        int flags = IFF_TUN;
        int fd,ret;
        char *i_dev = "/dev/net/tun";
        
        if((fd = open(i_dev,O_RDWR)) <0){
                perror("failed to open tun");
                return fd;
        }
        
        memset(&ifr,0,sizeof(ifr));
        
        ifr.ifr_flags = flags;
        
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

static int run_ipoc(int sock_fd,int tun_fd,quicly_conn_t *client)
{
        
}
int main(int argc,char **argv[])
{
        int sock_fd,tun_fd;
        int ret;
        int port;
        int maxfd;
        int option;
        char ifname[IFNAMSIZ] = "";
        char buffer[BUFSIZE];
        unsigned short type;
        char *host = "127.0.0.1";
        char *port = "4433";
        struct sockaddr sa;
        socklen_t salen;
        
        ptls_openssl_sign_certificate_t sign_certificate;
        ptls_context_t tlsctx = {
                .random_bytes   = ptls_open_ssl_random_bytes,
                .get_time       = &ptls_get_time,
                .key_exchange   = ptls_openssl_key_exchanges,
                .cipher_suites  = ptls_openssl_cipher_suites,
        };
        
        ctx = quicly_default_context;
        ctx.tls = &tlsctx;
        quicly_amend_ptls_context(ctx.tls);
        ctx.stream_open = &stream_open;

        while((option = getopt(argc,argv,"c:k:i:p:s:hd")) != 0){
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
                        case 'h':
                                usage();
                                break;
                        case 's':
                                type = SERVER;
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

        if(address_resolver(&sa,&salen,host,port,AF_INET,SOCK_DGRAM,0) != 0){
                exit(1);
        }

        sock_fd = socket(sa.ss_family,SOCK_DGRAM,0);
        if(sock_fd < 0){
                perror("failed to make a socket");
        }

        tun_fd = tun_alloc(ifname);
        if(tun_fd < 0){
               my_err("failed to connect tun/tap interface");
               exit(1);
        }
        
        if(type & SERVER){
                int reuseaddr = 1;
                setsocketopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr));
                if(bind(sock_fd,(struct sockaddr *)&sa,salen) != 0){
                        perror("failed to bind\n");
                        exit(1);
                }
        }
        else{
                struct sockaddr_in local;
                memset(&local,0,sizeof(local));
                if(bind(sock_fd,(struct sockaddr *)&local,sizeof(local)) != 0){
                        perror("failed to bind");
                        exit(1);
                }
                quicly_conn_t *client = NULL;
                ret = 0;
                if((ret = quicly_connect(&client,ctx,host,(struct sockaddr *)sa,salen,
                        &next_cid,NULL,NULL)) != 0){
                        fprintf(stderr,"quicly_connect failed:%d\n",ret);
                        exit(1);
                }
                quicly_stream_t *stream;
                quicly_open_stream(client,&stream,0);
        }
        
        return run_ipoc(sock_fd,tun_fd,client);
}

