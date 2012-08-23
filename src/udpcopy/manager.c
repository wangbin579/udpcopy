#include <xcopy.h>
#include <udpcopy.h>


static int             raw_sock  = -1;
static uint64_t        event_cnt = 0;
static uint32_t        localhost;
#if (UDPCOPY_OFFLINE)
static bool            read_pcap_over= false;
static pcap_t         *pcap = NULL;
static struct timeval  first_pack_time, last_pack_time, base_time, cur_time;
#endif

static bool process_packet(bool backup, char *packet, int length){
    char tmp_packet[RECV_BUF_SIZE];
    if (!backup){
        return process(packet, LOCAL);
    }else{
        memcpy(tmp_packet, packet, length);
        return process(tmp_packet, LOCAL);
    }
}

#if (!UDPCOPY_OFFLINE)
static void set_nonblock(int socket)
{
    int flags;
    flags = fcntl(socket, F_GETFL, 0);
    fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}

/* Initiate input raw socket */
static int init_input_raw_socket()
{
    int       sock, recv_buf_opt, ret;
    socklen_t opt_len;
    /* Copy ip datagram from IP layer*/
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (-1 == sock){
        perror("socket");
        log_info(LOG_ERR, "%s", strerror(errno));   
    }
    set_nonblock(sock);
    recv_buf_opt   = 67108864;
    opt_len = sizeof(int);
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_buf_opt, opt_len);
    if (-1 == ret){
        perror("setsockopt");
        log_info(LOG_ERR, "setsockopt:%s", strerror(errno));    
    }

    return sock;
}
#endif

/* Replicate packets for multiple-copying */
static void replicate_packs(char *packet, int length, int replica_num)
{
    int           i;
    struct udphdr *udp_header;
    struct iphdr  *ip_header;
    uint32_t      size_ip;
    uint16_t      orig_port, addition, dest_port, rand_port;
    
    ip_header  = (struct iphdr*)packet;
    size_ip    = ip_header->ihl << 2;
    udp_header = (struct udphdr*)((char *)ip_header + size_ip);
    orig_port  = ntohs(udp_header->source);

    tc_log_debug1(LOG_DEBUG, "orig port:%u", orig_port);

    rand_port = clt_settings.rand_port_shifted;
    for (i = 1; i < replica_num; i++){
        addition   = (((i << 1)-1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);

        tc_log_debug2(LOG_DEBUG, "new port:%u,add:%u", dest_port, addition);

        udp_header->source = htons(dest_port);
        process_packet(true, packet, length);
    }
}

static int dispose_packet(char *recv_buf, int recv_len, int *p_valid_flag)
{
    int            replica_num;
    char          *packet;
    bool           packet_valid = false;
    struct udphdr *udp_header;
    struct iphdr  *ip_header;

    packet = recv_buf;
    if (is_packet_needed((const char *)packet)){
        replica_num = clt_settings.replica_num;
        ip_header   = (struct iphdr*)packet;
        if (localhost == ip_header->saddr){
            if (0 != clt_settings.lo_tf_ip){
                ip_header->saddr = clt_settings.lo_tf_ip;
            }
        }
        if (replica_num > 1){
            packet_valid = process_packet(true, packet, recv_len);
            replicate_packs(packet, recv_len, replica_num);
        }else{
            packet_valid = process_packet(false, packet, recv_len);
        }
    }

    if (packet_valid){
        *p_valid_flag = 1;
    } else {
        *p_valid_flag = 0;
    }

    return SUCCESS;
}

/*
 * Retrieve raw packets
 */
static int retrieve_raw_sockets(int sock)
{
    int      err, recv_len, p_valid_flag = 0;
    char     recv_buf[RECV_BUF_SIZE];

    while (1) {

        recv_len = recvfrom(sock, recv_buf, RECV_BUF_SIZE, 0, NULL, NULL);
        if (recv_len < 0){
            err = errno;
            if (EAGAIN == err){
                break;
            }
            perror("recvfrom");
            log_info(LOG_ERR, "recvfrom:%s", strerror(errno));
        }
        if (0 == recv_len){
            log_info(LOG_ERR, "recv len is 0");
            break;
        }
        if (recv_len > RECV_BUF_SIZE){
            log_info(LOG_ERR, "recv_len:%d ,it is too long", recv_len);
            break;
        }

        if (FAILURE == dispose_packet(recv_buf, recv_len, &p_valid_flag)){
            break;
        }

    }
    return 0;
}

/* Check resource usage, such as memory usage and cpu usage */
static void check_resource_usage()
{
    int           who = RUSAGE_SELF;
    struct rusage usage;
    int           ret;
    ret = getrusage(who, &usage);
    if (-1 == ret){
        perror("getrusage");
        log_info(LOG_ERR, "getrusage:%s", strerror(errno)); 
    }
    /* Total amount of user time used */
    log_info(LOG_NOTICE, "user time used:%ld", usage.ru_utime.tv_sec);
    /* Total amount of system time used */
    log_info(LOG_NOTICE, "sys  time used:%ld", usage.ru_stime.tv_sec);
    /* Maximum resident set size (in kilobytes) */
    /* This is only valid since Linux 2.6.32 */
    log_info(LOG_NOTICE, "max memory size:%ld", usage.ru_maxrss);
    if (usage.ru_maxrss > clt_settings.max_rss){
        log_info(LOG_WARN, "occupies too much memory,limit:%ld",
                clt_settings.max_rss);
    }
}

#if (UDPCOPY_OFFLINE)
static 
uint64_t timeval_diff(struct timeval *start, struct timeval *cur)
{
    uint64_t msec;
    msec  = (cur->tv_sec - start->tv_sec)*1000;
    msec += (cur->tv_usec - start->tv_usec)/1000;
    return msec;
}

static 
bool check_read_stop()
{
    uint64_t history_diff = timeval_diff(&first_pack_time, &last_pack_time);
    uint64_t cur_diff     = timeval_diff(&base_time, &cur_time);
    uint64_t diff;
    tc_log_debug2(LOG_DEBUG, "diff,old:%llu,new:%llu", 
            history_diff, cur_diff);
    if (history_diff <= cur_diff){
        return false;
    }
    diff = history_diff - cur_diff;
    /* More than 1 seconds */
    if (diff > 1000){
        return true;
    }
    return false;
}

static int get_l2_len(const unsigned char *packet,
        const int pkt_len, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;

        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *)packet;
            switch (ntohs(eth_hdr->ether_type)) {
                case ETHERTYPE_VLAN:
                    return 18;
                    break;
                default:
                    return 14;
                    break;
            }
            break;

        case DLT_C_HDLC:
            return CISCO_HDLC_LEN;
            break;

        case DLT_LINUX_SLL:
            return SLL_HDR_LEN;
            break;
        default:
            log_info(LOG_ERR, "unsupported DLT type: %s (0x%x)", 
                    pcap_datalink_val_to_description(datalink), datalink);
            break;
    }
    return -1;
}

#ifdef FORCE_ALIGN
static unsigned char pcap_ip_buf[65536];
#endif

static 
unsigned char *get_ip_data(unsigned char *packet, 
        const int pkt_len, int *p_l2_len)
{
    int     l2_len;
    u_char *ptr;

    l2_len = get_l2_len(packet, pkt_len, pcap_datalink(pcap));
    *p_l2_len = l2_len;

    if (pkt_len <= l2_len){
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(packet)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(packet)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(packet)[l2_len]);
#endif
    return ptr;

}

void send_packets_from_pcap(int first)
{
    int                  l2_len, ip_pack_len, p_valid_flag = 0;
    bool                 stop;
    unsigned char       *pkt_data, *ip_data;
    struct pcap_pkthdr   pkt_hdr;  

    if (NULL == pcap || read_pcap_over){
        return;
    }
    gettimeofday(&cur_time, NULL);

    stop = check_read_stop();
    while (!stop) {
        pkt_data = (u_char *)pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL){
            if (pkt_hdr.caplen < pkt_hdr.len){
                log_info(LOG_WARN, "truncated packets,drop");
            }else{
                ip_data = get_ip_data(pkt_data, pkt_hdr.len, &l2_len);
                if (ip_data != NULL){
                    ip_pack_len = pkt_hdr.len - l2_len;
                    dispose_packet((char*)ip_data, ip_pack_len, &p_valid_flag);
                    if (p_valid_flag){
                        tc_log_debug0(LOG_DEBUG, "valid flag for packet");
                        if (first){
                            first_pack_time = pkt_hdr.ts;
                            first = 0;
                        }
                        last_pack_time = pkt_hdr.ts;
                    }else{
                        stop = false;
                        tc_log_debug0(LOG_DEBUG, "stop,invalid flag");
                    }
                }
            }
            stop = check_read_stop();
        }else{
            log_info(LOG_WARN, "stop,null from pcap_next");
            stop = true;
            read_pcap_over = true;
        }
    }
}

#endif

/* Dispose one event*/
void dispose_event(int fd)
{
    event_cnt++;
    if (fd == raw_sock){
        retrieve_raw_sockets(fd);
    }else{
        log_info(LOG_WARN, "source from other");
    }   
#if (UDPCOPY_OFFLINE)
    if (!read_pcap_over){
        log_info(LOG_DEBUG, "send_packets_from_pcap");
        send_packets_from_pcap(0);
    }
#endif
    if ((event_cnt%1000000) == 0){
        check_resource_usage();
    }
}

void udp_copy_exit()
{
    int i;
    fprintf(stderr, "exit udpcopy\n");
    if (-1 != raw_sock){
        close(raw_sock);
        raw_sock = -1;
    }
    send_close();
#if (UDPCOPY_OFFLINE)
    if (pcap != NULL) {
        pcap_close(pcap);
    }
#endif
    log_end();
    if (clt_settings.transfer.mappings != NULL){
        for (i = 0; i < clt_settings.transfer.num; i++){
            free(clt_settings.transfer.mappings[i]);
        }
        free(clt_settings.transfer.mappings);
        clt_settings.transfer.mappings = NULL;
    }
    exit(EXIT_SUCCESS);

}

void udp_copy_over(const int sig)
{
    long int pid   = (long int)syscall(SYS_gettid);
    log_info(LOG_WARN, "sig %d received, pid=%ld", sig, pid);
    exit(EXIT_SUCCESS);
}


/* Initiate udpcopy client */
int udp_copy_init(tc_event_loop_t *event_loop)
{
#if (UDPCOPY_OFFLINE)
    char                   *pcap_file, ebuf[PCAP_ERRBUF_SIZE];
#endif
    tc_event_t             *raw_socket_event;

    /* keep it temporarily */
    select_server_set_callback(dispose_event);

    localhost = inet_addr("127.0.0.1"); 

    /* Init output raw socket info */
    send_init();

#if (!UDPCOPY_OFFLINE)
    /* Init input raw socket info */
    raw_sock = init_input_raw_socket();
#endif
    if (raw_sock != -1){
        /* Add the input raw socket to select */
        raw_socket_event = tc_event_create(raw_sock, dispose_event_wrapper,
                                           NULL);
        if (raw_socket_event == NULL) {
            return FAILURE;
        }

        if (tc_event_add(event_loop, raw_socket_event, TC_EVENT_READ)
                == TC_EVENT_ERROR)
        {
            log_info(LOG_ERR, "add raw socket(%d) to event loop failed.",
                     raw_socket_event->fd);
            return FAILURE;
        }

        return SUCCESS;
    }else{
#if (UDPCOPY_OFFLINE)
        select_offline_set_callback(send_packets_from_pcap);
        pcap_file = clt_settings.pcap_file;
        if (pcap_file != NULL){
            if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL){
                log_info(LOG_ERR, "open %s" , ebuf);
                fprintf(stderr, "open %s\n", ebuf);
                return FAILURE;

            }else{
                gettimeofday(&base_time, NULL);
                log_info(LOG_NOTICE, "open pcap success:%s", pcap_file);
                log_info(LOG_NOTICE, "send the first packets here");
                send_packets_from_pcap(1);
            }
        }else{
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    }

    return SUCCESS;
}

/* keep it temporarily */
void dispose_event_wrapper(tc_event_t *efd)
{
    dispose_event(efd->fd);
}
