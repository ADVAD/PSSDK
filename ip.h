#ifndef __IP_H__
#define __IP_H__

typedef struct _IP_HEADER
 {
   unsigned char  Len:4,
                  Ver:4;
   unsigned char  ToS;
   unsigned short TotalLength;
   unsigned short Identification;
   unsigned short Offset:12,
                  Flags:4; 
   unsigned char  Ttl;
   unsigned char  Protocol;
   unsigned short Checksum;
   unsigned long  SrcAddr;
   unsigned long  DestAddr;
 }IP_HEADER, *PIP_HEADER;

#define IPTOS_LOWDELAY          0x10
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_RELIABILITY       0x04
#define IPTOS_MONETARY          0x02
#define IPTOS_RESERVED2         0x01
#define IPTOS_NONE              0x00

#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */

#define IP_VERSION_4            4      /* IPv4 */

#define DEFAULT_TTL             128  /* default Win ttl in the ip header.*/

#endif //__IP_H__
