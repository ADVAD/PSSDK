#include <windows.h>
#include <stdio.h>
#include <strsafe.h>


void ToSysFromRes() {

  HMODULE hMod;
  HRSRC hRes;
  HGLOBAL hGlob;
  BYTE *lpbArray;
  DWORD dwFileSize;
  HANDLE hFile;
  DWORD written;

  hMod=GetModuleHandle(NULL);
  if(hMod) {
    hRes=FindResource(hMod, MAKEINTRESOURCE(101),RT_RCDATA);
    if(hRes){
      hGlob=LoadResource(hMod,hRes);     //Теперь загружаем ресурс в память
      if(hGlob) {
        lpbArray=(BYTE*)LockResource(hGlob); //И, наконец, последнее - получаем указатель на начало массива
        if(lpbArray) {
          printf("AAAAAAA\n");
          dwFileSize=SizeofResource(hMod,hRes);     //Получаем размер массива (размер файла)
          if(dwFileSize) {
            hFile=CreateFile("C:\\Windows\\Sysnative\\drivers\\pssdk-proto.sys",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,0);
            WriteFile(hFile, lpbArray, dwFileSize,&written,NULL);
           CloseHandle(hFile);
          }
        }
      }
    }
  } 
}

/*
90000000  -144 4+44+16+60+20
1871250880F8FFFF00000000000000000100000000000000AEC8ED5A04AFD401000000000000000000000000 +44
3C000000
3C000000
3C000000 -60
00000000
FFFFFFFFFFFF50E549CF47D90806000108000604000150E549CF47D9C0A801B7000000000000C0A801C8000000000000000000000000000000000000 +60
0000000000000000000000000000000000000000 +20
*/

struct Packet {
  DWORD Len;
  BYTE ar1[44];
  DWORD DataLen1, DataLen2, DataLen3; 
  DWORD Zero;
  BYTE Data[];
} *Packet;






#include "ethernet.h" 
#include "arp.h" 
#include "ip.h" 


DumpPacket(PVOID pPacket) {
    char s[200];

    BYTE            *pPkt   = (BYTE*)pPacket;
    ETHERNET_HEADER *pEth   = (ETHERNET_HEADER *)pPacket;
    USHORT          EthType = htons(pEth->EthType);
    BYTE            *SrcMAC = (BYTE*)&pEth->EthSHost;
    BYTE            *DstMAC = (BYTE*)&pEth->EthDHost;

    printf("ETH %02X-%02X-%02X-%02X-%02X-%02X -> %02X-%02X-%02X-%02X-%02X-%02X  EthType: 0x%04hX\n",
        SrcMAC[0],SrcMAC[1],SrcMAC[2],SrcMAC[3],SrcMAC[4],SrcMAC[5],
        DstMAC[0],DstMAC[1],DstMAC[2],DstMAC[3],DstMAC[4],DstMAC[5], EthType);

    if (EthType == ETHERTYPE_ARP) {
      ARP_HEADER *pArp=(ARP_HEADER *)((BYTE*)pPacket+sizeof(ETHERNET_HEADER));

      StringCbPrintf( s, sizeof(s), "ARP %02X-%02X-%02X-%02X-%02X-%02X  %03i.%03i.%03i.%03i -> %02X-%02X-%02X-%02X-%02X-%02X  %03i.%03i.%03i.%03i\n",
         pArp->Sndr_Hw_Addr[0],pArp->Sndr_Hw_Addr[1],pArp->Sndr_Hw_Addr[2],pArp->Sndr_Hw_Addr[3],pArp->Sndr_Hw_Addr[4],pArp->Sndr_Hw_Addr[5],
         pArp->Sndr_Ip_Addr[0],pArp->Sndr_Ip_Addr[1],pArp->Sndr_Ip_Addr[2],pArp->Sndr_Ip_Addr[3],
         pArp->Rcpt_Hw_Addr[0],pArp->Rcpt_Hw_Addr[1],pArp->Rcpt_Hw_Addr[2],pArp->Rcpt_Hw_Addr[3],pArp->Rcpt_Hw_Addr[4],pArp->Rcpt_Hw_Addr[5],
         pArp->Rcpt_Ip_Addr[0],pArp->Rcpt_Ip_Addr[1],pArp->Rcpt_Ip_Addr[2],pArp->Rcpt_Ip_Addr[3]);

      printf(s);

    } else if (EthType == ETHERTYPE_IP) {
      IP_HEADER *pIp=(IP_HEADER *)((BYTE*)pPacket+sizeof(ETHERNET_HEADER));

      unsigned char *SrcIp = (unsigned char *) &pIp->SrcAddr;
      unsigned char *DstIp = (unsigned char *) &pIp->DestAddr;

      StringCbPrintf( s, sizeof(s), "IP %02X-%02X-%02X-%02X-%02X-%02X  %03i.%03i.%03i.%03i -> %02X-%02X-%02X-%02X-%02X-%02X  %03i.%03i.%03i.%03i\n",
         SrcMAC[0],SrcMAC[1],SrcMAC[2],SrcMAC[3],SrcMAC[4],SrcMAC[5],
         SrcIp[0], SrcIp[1], SrcIp[2], SrcIp[3],
         DstMAC[0],DstMAC[1],DstMAC[2],DstMAC[3],DstMAC[4],DstMAC[5],
         DstIp[0], DstIp[1], DstIp[2], DstIp[3]);

      printf(s);

   }

}

/*---------------------------------------------------------------------------------*/
int main() {
  SC_HANDLE hSCManager = 0;
  SC_HANDLE hSCObject = 0;
  SC_HANDLE hService = 0;
  SERVICE_STATUS ServiceStatus;

  struct InBuf {
    int fff, len;
    WCHAR s[257];
  } InBuf, OutBuf;

struct Buf1C78 {
  int i1;
  BYTE b1[0x74];
} Buf1C78;

struct Buf1C14 {
  int i1,i2,i3,i4,i5;
} Buf1C14;


struct Buf081C {
  int i1,i2,i3,i4,i5,i6,i7;
} Buf081C;

struct Buf2408 {
  int i1,i2;
} Buf2408;

struct Buf3804 {
  int i1;
} Buf3804;

  HKEY  hkResult;

  HANDLE hDevice;

  HANDLE hDosDev;

  DWORD junk     = 0;

  WCHAR s[257];

  BYTE PktBuf[10000];

  int i, j;

  int PktLen;

//#define DRVPATH "C:\\Windows\\System32\\drivers\\pssdk-proto.sys"
#define DRVPATH "C:\\Windows\\Sysnative\\drivers\\pssdk-proto.sys"

  BYTE OutBuffer[4096]; 

  ToSysFromRes();

//  if (CopyFile( "pssdk-proto.sys" , DRVPATH, TRUE)) { //bFailIfExists
//    printf("CopyFile OK\n");
//  }

  hSCManager = OpenSCManagerW( 0, 0, 0xF003F);
  printf("hSCManager = %X\n", hSCManager);

  CloseServiceHandle( hService);

  hService = OpenService( hSCManager, "pssdk-proto", 0xF01FF);
  printf("hService = %X\n", hService);

  LockServiceDatabase( hSCManager);
  printf("%i\n", CreateService(hSCManager, "pssdk-proto", "pssdk-proto", 0xF003F, 1, 3, 1, DRVPATH ,0, 0, 0, 0, 0));
  UnlockServiceDatabase( hSCManager);


  QueryServiceStatus( hService, &ServiceStatus);

  //SERVICE_RUNNING - 4  SERVICE_STOPPED -0x00000001
  printf("dwCurrentState = %X (SERVICE_RUNNING - 4  SERVICE_STOPPED -0x00000001)\n", ServiceStatus.dwCurrentState);

  //if (ServiceStatus.dwCurrentState == SERVICE_STOPPED)
  //StartService

/*
1: [esp+4] 006FF0A0 
2: [esp+8] 00700E20 
3: [esp+C] 00001000 
4: [esp+10] 0018ED08 
5: [esp+14] CD30BA4D 
6: [esp+18] 0018EF78 
7: [esp+1C] 006F9A70 
0047C6AC | FF15 10E04A00     | call dword ptr ds:[<&QueryServiceConfigW>]       |

00700E20  01 00 00 00 03 00 00 00 01 00 00 00 44 0E 70 00  ............D.p.  
00700E30  A8 0E 70 00 00 00 00 00 AC 0E 70 00 B0 0E 70 00  ?.p.....¬.p.°.p.  
00700E40  B4 0E 70 00 5C 00 3F 00 3F 00 5C 00 43 00 3A 00  ?.p.\.?.?.\.C.:.  
00700E50  5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00  \.W.i.n.d.o.w.s.  
00700E60  5C 00 53 00 79 00 73 00 6E 00 61 00 74 00 69 00  \.S.y.s.n.a.t.i.  
00700E70  76 00 65 00 5C 00 64 00 72 00 69 00 76 00 65 00  v.e.\.d.r.i.v.e.  
00700E80  72 00 73 00 5C 00 70 00 73 00 73 00 64 00 6B 00  r.s.\.p.s.s.d.k.  
00700E90  2D 00 70 00 72 00 6F 00 74 00 6F 00 2E 00 73 00  -.p.r.o.t.o...s.  
00700EA0  79 00 73 00 00 00 AD BA 00 00 AD BA 00 00 00 00  y.s....?...?....  
00700EB0  00 00 AD BA 70 00 73 00 73 00 64 00 6B 00 2D 00  ...?p.s.s.d.k.-.  
00700EC0  70 00 72 00 6F 00 74 00 6F 00 00 00 0D F0 AD BA  p.r.o.t.o....?.?  
00700ED0  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700EE0  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700EF0  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F00  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F10  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F20  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F30  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F40  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  
00700F50  0D F0 AD BA 0D F0 AD BA 0D F0 AD BA 0D F0 AD BA  .?.?.?.?.?.?.?.?  

*/


//  QueryServiceConfig( hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);
//  GetLastError

//ERROR_INSUFFICIENT_BUFFER 122 (0x7A)


/*
BOOL QueryServiceConfigA(
  SC_HANDLE               hService,
  LPQUERY_SERVICE_CONFIGA lpServiceConfig,
  DWORD                   cbBufSize,
  LPDWORD                 pcbBytesNeeded
);
*/
/*
1: [esp+4] 006FF0A0 
2: [esp+8] FFFFFFFF 
3: [esp+C] FFFFFFFF 
4: [esp+10] FFFFFFFF 
5: [esp+14] 0018F5BC L"C:\\Windows\\system32\\Drivers\\pssdk-proto.sys"
6: [esp+18] 00000000 
7: [esp+1C] 00000000 
8: [esp+20] 00000000 
9: [esp+24] 00000000 
10: [esp+28] 00000000 
11: [esp+2C] 00000000 
12: [esp+30] 00000001 
13: [esp+34] 0018EF78 


BOOL ChangeServiceConfigW(
  SC_HANDLE hService,
  DWORD     dwServiceType,
  DWORD     dwStartType,
  DWORD     dwErrorControl,
  LPCWSTR   lpBinaryPathName,
  LPCWSTR   lpLoadOrderGroup,
  LPDWORD   lpdwTagId,
  LPCWSTR   lpDependencies,
  LPCWSTR   lpServiceStartName,
  LPCWSTR   lpPassword,
  LPCWSTR   lpDisplayName
);

*/

  LockServiceDatabase( hSCManager);
  printf("ChangeServiceConfigW %i\n", ChangeServiceConfigW( hService, -1, -1, -1, L"C:\\Windows\\system32\\Drivers\\pssdk-proto.sys", 0, 0, 0, 0, 0, 0));
  UnlockServiceDatabase( hSCManager);

  //LockServiceDatabase
  //ChangeServiceConfig
  //UnlockServiceDatabase

/*
0046FF33 | E8 28C90000       | call <tcpdumpunp.QueryServiceStatusAndChange>    |
1: [esp] 006F9A70 
2: [esp+4] 006F9A70 
3: [esp+8] 006F9A9C 
4: [esp+C] 0018F5BC L"C:\\Windows\\system32\\Drivers\\pssdk-proto.sys"
5: [esp+10] 0000002D 
6: [esp+14] 003F005C 
7: [esp+18] 005C003F tcpdumpunp.005C003F
8: [esp+1C] 003A0043 
9: [esp+20] 0057005C tcpdumpunp.0057005C
10: [esp+24] 006E0069 
11: [esp+28] 006F0064 
12: [esp+2C] 00730077 
13: [esp+30] 0053005C tcpdumpunp.0053005C


*/


  if (!StartService( hService, 0, 0))
    printf("%X\n",GetLastError());

  QueryServiceStatus( hService, &ServiceStatus);

  //SERVICE_RUNNING - 4  SERVICE_STOPPED -0x00000001
  printf("dwCurrentState = %X (SERVICE_RUNNING - 4  SERVICE_STOPPED -0x00000001)\n", ServiceStatus.dwCurrentState);


  if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {

                   //0x80000002                                                                                                0x20019
    printf("RegOpenKeyEx %i\n", RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &hkResult));

    RegCloseKey( hkResult);

/*

FILE_FLAG_OVERLAPPED 0x40000000
FILE_ATTRIBUTE_NORMAL 128 (0x80)
FILE_FLAG_OPEN_REPARSE_POINT 0x00200000

.text:1000E5EC                 push    0               ; hTemplateFile
.text:1000E5EE                 push    60000080h       ; dwFlagsAndAttributes
.text:1000E5F3                 push    3               ; dwCreationDisposition
.text:1000E5F5                 push    0               ; lpSecurityAttributes
.text:1000E5F7                 push    0               ; dwShareMode
.text:1000E5F9                 push    0C0000000h      ; dwDesiredAccess
.text:1000E5FE                 lea     eax, [esp+228h+FileName]
.text:1000E602                 push    eax             ; lpFileName
.text:1000E603                 call    ds:CreateFileW
.text:1000E609                 pop     edi
*/

    //hDevice = CreateFile( "\\\\.\\pssdk-proto", 0xC0000000, 0, 0, 3, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, 0); //0x60000080, 0); // pssdk.idb 1000E5EC
    hDevice = CreateFileW( L"\\\\.\\Global\\pssdk-proto", 0xC0000000, 0, 0, 3, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, 0); //0x60000080, 0); // pssdk.idb 1000E5EC
    //hDevice = CreateFileW( L"\\\\.\\Global\\pssdk-proto", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // pssdk.idb 1000E5EC
    printf( "hDevice =%i\n", hDevice);

/*
.text:00472125 8B 8B 8C 00 00+                mov     ecx, [ebx+8Ch]
.text:0047212B 8D 42 E8                       lea     eax, [edx-18h]
.text:0047212E 50                             push    eax             ; lpOverlapped
.text:0047212F 6A 00                          push    0               ; lpBytesReturned
.text:00472131 FF 72 18                       push    dword ptr [edx+18h] ; nOutBufferSize
.text:00472134 52                             push    edx             ; lpOutBuffer
.text:00472135 6A 00                          push    0               ; nInBufferSize
.text:00472137 6A 00                          push    0               ; lpInBuffer
.text:00472139 68 36 00 00 80                 push    80000036h       ; dwIoControlCode
.text:0047213E FF 71 18                       push    dword ptr [ecx+18h] ; hDevice
.text:00472141 FF 15 C4 E0 4A+                call    ds:DeviceIoControl
.text:00472147 8B C8                          mov     ecx, eax
.text:00472149 85 C9                          test    ecx, ecx
.text:0047214B 75 14                          jnz     short loc_472161
.text:0047214D FF 15 58 E0 4A+                call    ds:GetLastError
.text:00472153 33 C9                          xor     ecx, ecx
.text:00472155 3D E5 03 00 00                 cmp     eax, 3E5h       ; ERROR_IO_PENDING
.text:00472155                                                        ; 997 (0x3E5)
.text:00472155                                                        ; Overlapped I/O operation is in progress.
*/


//Если операция завершается успешно, DeviceIoControl возвращает ненулевое значение.
//Если операция завершается ошибкой, DeviceIoControl возвращает нуль. Чтобы получить дополнительную информацию об ошибке, вызовите GetLastError.



//DeviceIoControl 0x0047BD39 hDev:138 ioCode:80000000 inBuf:706438 inSz:210 outBuf:706438 outSize:210 btReturned:0 Overlapped:19F830  
//                  FFFFFFFF5E0000005C004400650076006900630065005C007B00440031003700460036003000390041002D00330045003000   \Device\{917
//0 706438 FFFFFFFF FFFFFFFF5E0000005C0044006F00730044006500760069006300650073005C0070007300730064006B005F00310035000000   \Dos

    InBuf.fff=0; //-1;
    InBuf.len=0x5e; // e;
    lstrcpynW( InBuf.s, L"\\Device\\{D17F609A-3E02-4B0F-A20D-C81897372D00}", 0x210);
    //lstrcpynW( InBuf.s, L"\\Device\\{F6E57269-ECB4-42A9-AF52-96CF38D074FF}", 0x210); //NII
    //lstrcpynW( InBuf.s, L"\\Device\\{C9DF2758-144D-494B-9933-6579794203FF}", 0x210); //NII

/*
1.\Device\NdisWanBh (WAN Miniport (Network Monitor))
2.\Device\{C3EEA6B7-A397-4459-9228-D41CAF584919} (VMware Virtual Ethernet Adapter for VMnet8)
3.\Device\{F6E57269-ECB4-42A9-AF52-96CF38D074FF} (Realtek PCIe GBE Family Controller)
4.\Device\{C9DF2758-144D-494B-9933-6579794203FF} (Realtek PCIe GBE Family Controller)
5.\Device\{66A13223-37E1-4761-A67B-170124912B49} (VMware Virtual Ethernet Adapter for VMnet1)
6.\Device\{70FC34CA-0143-40A4-80DF-39326B74C17B} (Realtek RTL8188ETV Wireless LAN 802.11n USB 2.0 Network Adapter)
*/


    OutBuffer[0] = 0;
    printf( "Do %ls %x %x %x %x\n", InBuf.s, InBuf.fff, InBuf.len, sizeof(InBuf),(lstrlenW(InBuf.s)+1)*2);
    printf( "%i ", DeviceIoControl( hDevice, 0x80000000, &InBuf, 0x210, &OutBuf, 0x210, &junk, 0)); // можно один буфер in out
    printf( "Posle InBuf.s %ls %x %x %x\n", InBuf.s, InBuf.fff, InBuf.len, sizeof(InBuf));
    printf( "Posle OutBuf.s %ls %x %x %x\n", OutBuf.s, OutBuf.fff, OutBuf.len, sizeof(OutBuf));
  

    lstrcpyW(s,L"\\\\.");
    lstrcatW(s, &OutBuf.s[11]);

    //762F3EFC 47045F CreateFileW( L"\\\\.\\pssdk_595", 18F620,  C0000000, 0, 0, 3, 60000080, 0, 5C005C) 94
    hDosDev = CreateFileW( s, 0xC0000000, 0, 0, 3, 0x60000080, 0); // pssdk.idb 1000E5EC
    printf( "%ls hDosDev =%i\n", s, hDosDev);

    //47BD39 DeviceIoControl( 94, 80000038,  A84650, 4, A84650, 4, 0, 18F860) 01000000)
    memset(&Buf3804,0,sizeof(Buf3804));
    Buf3804.i1=1;
    printf( "80000038 %i ", DeviceIoControl( hDosDev, 0x80000038, &Buf3804, sizeof(Buf3804), &Buf3804, sizeof(Buf3804), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 8000001C,  A86340, 78, A86340, 78, 0, 18F860) 060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    memset(&Buf1C78,0,sizeof(Buf1C78));
    Buf1C78.i1=6;
    printf( "8000001C %i ", DeviceIoControl( hDosDev, 0x8000001C, &Buf1C78, sizeof(Buf1C78), &Buf1C78, sizeof(Buf1C78), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 80000024,  A84650, 8, A84650, 8, 0, 18F860) 0000000000000000)
    memset(&Buf2408,0,sizeof(Buf2408));
    Buf2408.i1=0;
    Buf2408.i2=0;
    printf( "80000024 %i ", DeviceIoControl( hDosDev, 0x80000024, &Buf2408, sizeof(Buf2408), &Buf2408, sizeof(Buf2408), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 80000008,  A86340, 1C, A86340, 1C, 0, 18F860) 00000000 01000000 0E010100 00000000 00000000 04000000 20000000)
    memset(&Buf081C,0,sizeof(Buf081C));
    Buf081C.i1=0;
    Buf081C.i2=1;
    Buf081C.i3=0x0001010e;
    Buf081C.i4=0;
    Buf081C.i5=0;
    Buf081C.i6=4;
    Buf081C.i7=0x20;
    printf( "80000008 %i ", DeviceIoControl( hDosDev, 0x80000008, &Buf081C, sizeof(Buf081C), &Buf081C, sizeof(Buf081C), &junk, 0)); // можно один буфер in out

    //47BD39 DeviceIoControl( 94, 80000008,  A86340, 1C, A86340, 1C, 0, 18F878) 00000000 00000000 07010100 00000000 00000000 04000000 00000000)
    memset(&Buf081C,0,sizeof(Buf081C));
    Buf081C.i1=0;
    Buf081C.i2=0;
    Buf081C.i3=0x00010107;
    Buf081C.i4=0;
    Buf081C.i5=0;
    Buf081C.i6=4;
    Buf081C.i7=0;
    printf( "80000008 %i ", DeviceIoControl( hDosDev, 0x80000008, &Buf081C, sizeof(Buf081C), &Buf081C, sizeof(Buf081C), &junk, 0)); // можно один буфер in out

    //47BD39 DeviceIoControl( 94, 80000008,  A86340, 1C, A86340, 1C, 0, 18F86C) 00000000 01000000 0E010100 00000000 00000000 04000000 20000000)
    memset(&Buf081C,0,sizeof(Buf081C));
    Buf081C.i1=0;
    Buf081C.i2=1;
    Buf081C.i3=0x0010010E;
    Buf081C.i4=0;
    Buf081C.i5=0;
    Buf081C.i6=4;
    Buf081C.i7=0x20;
    printf( "80000008 %i ", DeviceIoControl( hDosDev, 0x80000008, &Buf081C, sizeof(Buf081C), &Buf081C, sizeof(Buf081C), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 8000001C,  A86430, 78, A86430, 78, 0, 18F8AC) 060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    memset(&Buf1C78,0,sizeof(Buf1C78));
    Buf1C78.i1=6;
    printf( "8000001C %i ", DeviceIoControl( hDosDev, 0x8000001C, &Buf1C78, sizeof(Buf1C78), &Buf1C78, sizeof(Buf1C78), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 8000001C,  A86430, 14, A86430, 14, 0, 18F8AC) 03000000 0C000000 01000000 06000000 00000400)
    memset(&Buf1C14,0,sizeof(Buf1C14));
    Buf1C14.i1=3;
    Buf1C14.i2=0xC;
    Buf1C14.i3=1;
    Buf1C14.i4=6;
    Buf1C14.i5=0x00040000;
    //Buf1C14 = (3, 0xC, 1, 6, 0x00040000);
    printf( "8000001C %i ", DeviceIoControl( hDosDev, 0x8000001C, &Buf1C14, sizeof(Buf1C14), &Buf1C14, sizeof(Buf1C14), &junk, 0)); // можно один буфер in out


    //47BD39 DeviceIoControl( 94, 8000001C,  A86430, 78, A86430, 78, 0, 18F8AC) 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    memset(&Buf1C78,0,sizeof(Buf1C78));
    // printf("%0x\n",sizeof(Buf1C78)); //выдает 78
    Buf1C78.i1=1;
    printf( "8000001C %i ", DeviceIoControl( hDosDev, 0x8000001C, &Buf1C78, sizeof(Buf1C78), &Buf1C78, sizeof(Buf1C78), &junk, 0)); // можно один буфер in out

do {

    memset(&PktBuf,0,sizeof(PktBuf));

    printf( "%i ", DeviceIoControl( hDosDev, 0x80000036, NULL, 0, &PktBuf, sizeof(PktBuf), &junk, 0)); // можно один буфер in out
    printf( "junk=%i\n", junk);

    //DeviceIoControl( B8, 8000000E, 0, 0, 2290A70, 613, 0,  1DE1A8C); A90000000000000082637D849DADD401000000000000000000000000EA050000400000004000000001005E0000FC1C6F65CE")
    //printf( "%i ", DeviceIoControl( hDosDev, 0x8000000E, NULL, 0, &PktBuf, 1000, &junk, 0)); // винда уходит в синсй экран
    //printf( "junk=%i\n", junk);


//    for (i=0; i<32; i++) printf( "%0X", PktBuf[i+128]);

    for (i=0; i<64; i++) printf( "%02X", PktBuf[i]);
    printf( "\n\n");

    //for (i=64; i<sizeof(PktBuf); i++) printf( "%02X", PktBuf[i]);
    //printf( "\n\n");


    for (i=64; i+sizeof(Packet)<sizeof(PktBuf); i+=Packet->Len) {
      Packet=&PktBuf[i];
      if (Packet->Len==0) break;
      printf("\n%i %i %i %i %i %i\n", i, Packet->Len, Packet->Zero, Packet->DataLen1, Packet->DataLen2, Packet->DataLen3);
      for (j=0; j<Packet->DataLen3; j++) printf( "%02X", Packet->Data[j]);
      printf( "\n");
      DumpPacket(Packet->Data);
    }

} while (1); //GetKeyState(VK_ESCAPE) & 0x8000); /*check if high-order bit is set (1 << 15)*/


//      PktLen=*(int*)&PktBuf[i];
//      printf("%i %i\n", i, PktLen);
//    }

    //printf("\n%x %i\n", *(int*)&PktBuf[1], PktLen);

    CloseHandle( hDosDev);

    CloseHandle( hDevice);

 
 }


  CloseServiceHandle( hService);

  CloseServiceHandle( hSCManager);


  return 0;
}