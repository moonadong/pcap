#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800)
  {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol == IPPROTO_TCP)
    {
      printf("=================================\n");
      printf("Source Mac      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      printf("Destnation Mac  : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
      printf("Source Ip       : %s\n", inet_ntoa(ip->iph_sourceip));
      printf("Destnation Ip   : %s\n", inet_ntoa(ip->iph_destip));
      printf("Protocol        : TCP\n");
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
      printf("Source Port     : %d\n", ntohs(tcp->tcp_sport));
      printf("Destnation Port : %d\n", ntohs(tcp->tcp_dport));
      int tcp_header_size = TH_OFF(tcp) * 4;
      unsigned char *message = (unsigned char *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp_header_size);
      int total_headers_size = ip->iph_ihl * 4 + tcp_header_size;
      int message_size = ntohs(ip->iph_len) - total_headers_size;

      printf("message (%d bytes): \n", message_size);
      for (int i = 0; i < message_size && i < 200; i++)
      {
        printf("%02X ", message[i]);
        if (i % 8 == 7)
          printf("\n");
      }
      printf("\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "tcp";
  struct bpf_program fp;
  bpf_u_int32 net;
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", "ens33", errbuf);
    return (2);
  }
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0)
  {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);
  return 0;
}
