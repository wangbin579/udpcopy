
#include <xcopy.h>
#include <udpcopy.h>


static time_t   last_record_time = 0;

static uint64_t clt_udp_cnt      = 0;
static uint64_t clt_udp_send_cnt = 0;

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
 * filter packets 
 */
bool is_packet_needed(const char *packet)
{
    bool           is_needed = false;
    uint16_t       size_ip, size_udp, tot_len;
    struct iphdr  *ip_header;
    struct udphdr *udp_header;

    ip_header = (struct iphdr*)packet;

    /* check if it is a udp packet */
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

    /* filter the packets we do care about */
    if(LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, udp_header->dest, CHECK_DEST)){
        is_needed = true;
        clt_udp_cnt++;
        strace_pack(LOG_DEBUG, ip_header, udp_header);
    }

    return is_needed;

}


void ip_fragmentation(struct iphdr *ip_header, struct udphdr *udp_header)
{
    int           max_pack_no, index, i;
    char          tmp_buf[RECV_BUF_SIZE];
    ssize_t       send_len;
    uint16_t      offset, head_len, size_ip, tot_len,
                  remainder, payload_len;
    struct iphdr *tmp_ip_header;

    size_ip    = ip_header->ihl << 2;
    tot_len    = ntohs(ip_header->tot_len);
    head_len   = size_ip + sizeof(struct udphdr);

    /* dispose the first packet here */
    memcpy(tmp_buf, (char *)ip_header, size_ip);
    offset = clt_settings.mtu - size_ip;
    if (offset % 8 != 0) {
        offset = offset / 8;
        offset = offset * 8;
    }
    payload_len = offset;

    tmp_ip_header = (struct iphdr *)tmp_buf;
    tmp_ip_header->frag_off = htons(0x2000);

    index  = size_ip;
    memcpy(tmp_buf + size_ip, ((char *)ip_header) + index, payload_len);
    index      = index + payload_len;
    remainder  = tot_len - size_ip - payload_len;
    send_len   = send_ip_packet(tmp_ip_header, size_ip + payload_len);
    if (-1 == send_len) {
        log_info(LOG_ERR, "send to back error,packet size:%d",
                size_ip + payload_len);
        return;
    }

    clt_udp_send_cnt++;

    max_pack_no = (offset + remainder - 1)/offset - 1;

    for (i = 0; i <= max_pack_no; i++) {

        memcpy(tmp_buf, (char *)ip_header, size_ip);

        tmp_ip_header = (struct iphdr *)tmp_buf;
        tmp_ip_header->frag_off = htons(offset >> 3);

        if (i == max_pack_no) {
            payload_len = remainder;
        }else {
            tmp_ip_header->frag_off |= htons(IP_MF);
            remainder = remainder - payload_len;
        }

        memcpy(tmp_buf + size_ip, ((char *)ip_header) + index, payload_len);
        index     = index + payload_len;
        offset    = offset + payload_len;

        send_len  = send_ip_packet(tmp_ip_header, size_ip + payload_len);
        if (-1 == send_len) {
            log_info(LOG_ERR, "send to back error,cont len:%d",
                    size_ip + payload_len);
            return;
        }
        clt_udp_send_cnt++;
    }
}

/*
 * the main procedure for processing the filtered packets
 */
bool process(char *packet, int pack_src)
{
    int                      diff;
    time_t                   cur_time;
    ssize_t                  send_len;
    uint16_t                 size_ip, tot_len;
    struct iphdr            *ip_header;
    struct udphdr           *udp_header;
    ip_port_pair_mapping_t  *test;

    /* TODO time update will be optimized later */
    cur_time   = time(0);
    if (last_record_time != 0) {
        diff = cur_time - last_record_time;
        if (diff > 3) {
            log_info(LOG_INFO, "udp packets captured:%llu,packets sent:%llu",
                    clt_udp_cnt, clt_udp_send_cnt);
            last_record_time = cur_time;
        }
    } else {
        last_record_time = cur_time;
    }

    ip_header  = (struct iphdr *)packet;
    size_ip    = ip_header->ihl<<2;
    tot_len    = ntohs(ip_header->tot_len);
    udp_header = (struct udphdr*)((char *)ip_header + size_ip);

    test = get_test_pair(&(clt_settings.transfer),
            ip_header->daddr, udp_header->dest);
    ip_header->daddr = test->target_ip;
    udp_header->dest = test->target_port;

    udpcsum(ip_header, udp_header);
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *)ip_header, size_ip); 

    /* check if it needs fragmentation */
    if (tot_len > clt_settings.mtu) {
        ip_fragmentation(ip_header, udp_header);
    } else {
        send_len   = send_ip_packet(ip_header, tot_len);
        if (-1 == send_len) {
            log_info(LOG_ERR, "send to back error,tot_len:%d", tot_len);
            return false;
        }
        clt_udp_send_cnt++;
    }

    return true;
}

