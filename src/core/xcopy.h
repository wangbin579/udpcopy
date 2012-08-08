#ifndef  _XCOPY_H_INC
#define  _XCOPY_H_INC

/* Set raw socket receiving buffer size */
#define RECV_BUF_SIZE 65536
/* Default mtu for output raw socket */
#define DEFAULT_MTU   1500

/* Max fd number for select */
#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM-1)

#define MAX_ALLOWED_IP_NUM 32

/* Constants for netlink protocol */
#define FIREWALL_GROUP  0

/* In defence of occuping too much memory */
#define MAX_MEMORY_SIZE 524288

/* Where is the packet from (source flag) */
#define UNKNOWN 0
#define REMOTE  1
#define LOCAL   2

#define CHECK_DEST 1
#define CHECK_SRC  2

/* The results of operation*/
#define SUCCESS   0
#define FAILURE  -1

/* Bool constants*/
#if HAVE_STDBOOL_H
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif 


#include "config.h"
#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#if (UDPCOPY_OFFLINE)
#include <pcap.h>
#endif


#if (UDPCOPY_OFFLINE)
#define ETHER_ADDR_LEN 0x6
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16

/*  
 *  Ethernet II header
 *  Static header size: 14 bytes          
 */ 
struct ethernet_hdr{
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};
#endif


int daemonize();

#include <tc_time.h>

#include <tc_event.h>
#include <tc_select_module.h>
#include <select_server_wrapper.h>
#include <select_server.h>
#include <log.h>

#endif   /* ----- #ifndef _XCOPY_H_INC ----- */

