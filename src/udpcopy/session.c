
#include <xcopy.h>
#include <udpcopy.h>

static void
strace_pack(int level, struct iphdr *ip_header,
        struct udphdr *udp_header)
{

    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    uint32_t        pack_size;
    struct in_addr  src_addr, dst_addr;

    src_addr.s_addr = ip_header->saddr;
    tmp_buf         = inet_ntoa(src_addr);
    strcpy(src_ip, tmp_buf);
    dst_addr.s_addr = ip_header->daddr;
    tmp_buf         = inet_ntoa(dst_addr);
    strcpy(dst_ip, tmp_buf);

    pack_size       = ntohs(ip_header->tot_len);
    tc_log_debug5(level, 
            "from client %s:%u-->%s:%u,len %u",
            src_ip, ntohs(udp_header->source), dst_ip,
            ntohs(udp_header->dest), pack_size);
}

/*
 * Filter packets 
 */
bool is_packet_needed(const char *packet)
{
    bool           is_needed = false;
    uint16_t       size_ip, size_udp, tot_len;
    struct iphdr  *ip_header;
    struct udphdr *udp_header;

    ip_header = (struct iphdr*)packet;

    /* Check if it is a udp packet */
    if(ip_header->protocol != IPPROTO_UDP){
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    if (size_ip < 20) {
        log_info(LOG_WARN, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    udp_header = (struct udphdr*)((char *)ip_header + size_ip);
    size_udp   = ntohs(udp_header->len);
    if (size_udp < sizeof(struct udphdr)) {
        log_info(LOG_WARN, "Invalid udp header len: %d bytes,pack len:%d",
                size_udp, tot_len);
        return is_needed;
    }

    /* Here we filter the packets we do care about */
    if(LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, udp_header->dest, CHECK_DEST)){
        is_needed = true;
        strace_pack(LOG_DEBUG, ip_header, udp_header);
    }

    return is_needed;

}


/*
 * The main procedure for processing the filtered packets
 */
bool process(char *packet, int pack_src)
{
    ssize_t                  send_len;
    uint16_t                 size_ip, tot_len;
    struct iphdr            *ip_header;
    struct udphdr           *udp_header;
    ip_port_pair_mapping_t  *test;

    ip_header  = (struct iphdr*)packet;
    size_ip    = ip_header->ihl<<2;
    tot_len    = ntohs(ip_header->tot_len);
    udp_header = (struct udphdr*)((char *)ip_header + size_ip);

    test = get_test_pair(&(clt_settings.transfer),
            ip_header->saddr, udp_header->source);
    ip_header->daddr = test->target_ip;
    udp_header->dest = test->target_port;

    udpcsum(ip_header, udp_header);
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *)ip_header, size_ip); 

    send_len   = send_ip_packet(ip_header, tot_len);
    printf("send len:%d,tot_len:%d\n",send_len, tot_len);
    if (-1 == send_len) {
        log_info(LOG_ERR, "send to back error,tot_len:%d", tot_len);
        return false;
    }

    return true;
}

