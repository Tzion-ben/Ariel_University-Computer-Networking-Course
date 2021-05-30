// mySniffing_Spoofing.c
// @Tzion Beniaminov
// 01.2021
// Snipping ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <unistd.h>

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define IP_MAXPACKET 65535
#define ICMP_HDRLEN 8 
#define IP4_HDRLEN 20
///////////////////////////////////////////////////////////////////////////////
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};
/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmpId;    //Used for identifying request
  unsigned short int icmpSeq;    //Sequence number
};
/**********************************************
 *Packet Capturing using raw libpcap
 **********************************************/
unsigned short calculate_checksum(unsigned short * paddress, int len);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void send_raw_ip_packet(struct ipheader* ip);
//////////////////////////////////////////////////////////
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip_new proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("br-298100985c4e", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
 

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet_in)
{
  struct ethheader *eth = (struct ethheader *)packet_in;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip_old = (struct ipheader *)
                           (packet_in + sizeof(struct ethheader)); 

      //pull out the ip of the destantion and source of the victim
    char src_ofTheVictim[30];//sorce will by tthe new destation
    char dst_ofTheVictim[30];//the destation eill by the new source
    memset (&src_ofTheVictim, 0, sizeof (char*));
    memset (&dst_ofTheVictim, 0, sizeof (char*));
    //sprintf(src,"%d",ip_new->iph_sourceip.s_addr);
    //printf("%s",inet_ntoa(ip_new->iph_sourceip));
    //src_ofTheVictim = inet_ntoa(ip_new->iph_sourceip);
    //dst_ofTheVictim = inet_ntoa(ip_new->iph_destip);

    memcpy (src_ofTheVictim, inet_ntoa(ip_old->iph_sourceip), ICMP_HDRLEN);
    memcpy (dst_ofTheVictim, inet_ntoa(ip_old->iph_destip), ICMP_HDRLEN);

    printf("%s \n",inet_ntoa(ip_old->iph_sourceip));
    printf("%s \n",inet_ntoa(ip_old->iph_destip));
    /////////////////////////////////////////////////////

  // Combine the packet 
    char packet[IP_MAXPACKET];
    memset(packet,0,IP_MAXPACKET);
    

    char *meggase = "This is spoofed reply.\n";
    int meggase_len = strlen(meggase) + 1;
 
    char *data = (char *)packet+ sizeof(struct ipheader)+sizeof(struct icmp); 
    /**************************************************************/

   struct ipheader *ip_new = (struct ipheader *) packet;
   ip_new->iph_ver = 4;
   ip_new->iph_ihl = 5;
   ip_new->iph_ttl = 20;
  
   ip_new->iph_protocol = IPPROTO_ICMP;
   ip_new->iph_len = htons (IP4_HDRLEN + ICMP_HDRLEN + meggase_len);
   
    
   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (packet + sizeof(struct ipheader));
   icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = calculate_checksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) packet;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip_new->iph_sourceip.s_addr = inet_addr(dst_ofTheVictim);
   ip_new->iph_destip.s_addr = inet_addr(src_ofTheVictim);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                   sizeof(struct icmpheader));
   //ip->iph_len = htons(1000);
   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);

   return;
    }
}


// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}