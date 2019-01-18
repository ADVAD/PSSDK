#ifndef __ETHERNET_H__
#define __ETHERNET_H__

typedef struct _ETHERNET_HEADER
 {
   unsigned char  EthDHost[6];
   unsigned char  EthSHost[6];
   unsigned short EthType;
 }ETHERNET_HEADER, *PETHERNET_HEADER;

#define ETHERTYPE_PUP    0x0200  /* PUP protocol */
#define ETHERTYPE_IP     0x0800  /* IP protocol */
#define ETHERTYPE_ARP    0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP 0x8035 /* Reverse Addr. resolution protocol */

#endif //__ETHERNET_H__

