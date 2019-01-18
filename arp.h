#ifndef __ARP_H__
#define __ARP_H__

typedef struct _ARP_HEADER
 {
   unsigned short Hw_Type;
   unsigned short Prot_Type;
   unsigned char  Hw_Addr_Size;              // Mac Address Size
   unsigned char  Prot_Addr_Size;            // Protocol Address Size
   unsigned short Operation;                 //
   unsigned char  Sndr_Hw_Addr[6];           // Our Mac Address
   unsigned char  Sndr_Ip_Addr[4];           // Our IP  Address
   unsigned char  Rcpt_Hw_Addr[6];           //  -------- Zero
   unsigned char  Rcpt_Ip_Addr[4];           // Dest IP Addrerss
   unsigned char  Padding[18];               // Non Use
 }ARP_HEADER, *PARP_HEADER;

// For Hw_Type
#define HW_TYPE_ETH10           1  // Eternet 10 Mbps
#define HW_TYPE_ETH3            2  // Eternet 3 Mbps (Experimental)
#define HW_TYPE_X25             3  // X 25
#define HW_TYPE_TOKENRING       4  // Token Ring
#define HW_TYPE_CHAOS           5  // Chaos
#define HW_TYPE_IEEE802         6  // IEEE 802
#define HW_TYPE_ARCNET          7  // ARCNET

// For Operation
#define ARP_OP_ARP_QUERY        1  // ARP query
#define ARP_OP_ARP_RESP         2  // ARP response
#define ARP_OP_RARP_QUERY       3  // RARP query
#define ARP_OP_RARP_RESP        4  // RARP response

#endif //__ARP_H__

