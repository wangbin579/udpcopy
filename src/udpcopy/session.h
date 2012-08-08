
#ifndef  _UDP_SESSION_H_INC
#define  _UDP_SESSION_H_INC


/* Global functions */
bool process(char *packet, int pack_src);
bool is_packet_needed(const char *packet);

#endif   /* ----- #ifndef _UDP_SESSION_H_INC ----- */

