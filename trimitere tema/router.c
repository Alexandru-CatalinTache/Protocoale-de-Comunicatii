#include <queue.h>
#include "skel.h"
#include <sys/stat.h>
#include <fcntl.h>

#define NUMAR_MARE 100000

typedef struct {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} nod;

typedef struct {
	uint32_t ip;
	uint8_t mac[6];
} arp_entry;

nod *get_best_route(uint32_t dest_ip, nod* r_table, int rtable_size) {            // functie de gasit next_hop
	int ok = 0;
	int v[NUMAR_MARE];
	uint32_t max;
	int k = 0;
	for(int i = 0; i < rtable_size; i++)
	{	
		if(ok == 0){
		if((dest_ip & r_table[i].mask) == r_table[i].prefix)
		{
				v[k] = i;
				k++;
				max = r_table[i].mask;
				ok =1;
		}
		}
		if(ok == 1) {
			if((dest_ip & r_table[i]. mask) == r_table[i]. prefix)
		{
				v[k] = i;
				k++;
				if(max < r_table[i].mask)
				{
					max = r_table[i]. mask;
				}
		}
		}

	}

	for(int i =0; i < k; i++)
	{
		if(r_table[v[i]].mask == max)
		{
			return &r_table[v[i]];
		}
	}
	return NULL;
}

arp_entry *get_arp_entry(uint32_t ip, int arp_table_len, arp_entry* arp_table) {     
    
	for(int i = 0; i < arp_table_len; i++)
	{
		if(ip == arp_table[i].ip)
		{
			return &arp_table[i];
		}
	}
    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	int fd;
    DIE((fd=open(argv[1],O_RDONLY))==-1,"open file");
	char ch;
	int count = 0;
	
	while(read(fd, &ch, 1) != 0){                 
        
        if(ch ==' ' || ch == '\n')  
            count++;  
    }  
	
	nod* r_table = (nod*) malloc(sizeof(nod)* (count/4));
    int size = (count/4);
	int i;
	int k = 0;
	char *word = (char*) malloc(sizeof(char)*16);           


	lseek(fd, 0, SEEK_SET);
	for(i = 0; i < size; i++){
		k = 0;
		
		while(k < 4){
				
			read(fd, &ch, 1);
			int lung = 0;
			while((ch != ' ') && (ch!= '\n')){
				word[lung] = ch;
				lung++;
				
				read(fd, &ch, 1);

			}
			
		word[lung] = '\0';

		struct in_addr in;
		if(k == 0){
			 inet_aton(word, &in);
			r_table[i].prefix =  in.s_addr;
		}
		
		if(k == 1){
			inet_aton(word, &in);
			r_table[i].next_hop = in.s_addr;
		}
		if(k == 2){
			inet_aton(word, &in);
			r_table[i].mask = in.s_addr;
		}
		if(k == 3){
			
			r_table[i].interface = atoi(word); 
		}
		k++;
	}
	}
	
	
	/*for(i = 0; i < size; i++){              verificare realizare r_table
		struct in_addr in;
		in.s_addr = r_table[i].prefix;
		printf("%s\n", inet_ntoa(in));
	}*/
	 
	 int numar_cautari_in_arp_table = 0;  // variabila pt a tine minte a cata oara intru in arp_table
										 // astfel daca e prima oara at arp_table e goala si deci nu am ce 
										 //sa caut in ea => fac arp request si reply

	arp_entry* arp_table = (arp_entry*) malloc(sizeof(arp_entry)*NUMAR_MARE);

	struct queue *q = queue_create();  //coada de pachete ce necesita arp request si reply

	int size_arp_table = 0;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */



		struct ether_header *eth_hdr = (struct ether_header *) m.payload; 


		struct  arp_header *arpheader = parse_arp(m.payload);         //verificare arp
		if(arpheader != NULL){

		if(arpheader->op == htons(ARPOP_REPLY)){
			

			
			packet *p = queue_deq(q);
			struct iphdr *ip_hdr = (struct iphdr *)(p->payload + sizeof(struct ether_header));
			nod *r =  get_best_route(ip_hdr->daddr, r_table, size);


			//adaugare in arp_table a ip si mac
			arp_table[size_arp_table].ip = r->next_hop;
			memcpy(arp_table[size_arp_table].mac, arpheader->sha, 6);

			size_arp_table++;

			//arp_entry *a = get_arp_entry(r->next_hop, size_arp_table, arp_table);
			memcpy(eth_hdr->ether_dhost, arpheader->sha, 6);
		
		    get_interface_mac(r->interface, eth_hdr->ether_shost);
			send_packet(r->interface, p);
		}  


		else {   //Arp request

			struct ether_header *eth_hdr2 = (struct ether_header*) (malloc (sizeof(struct ether_header)));


			char *ip = get_interface_ip(m.interface);  //saddr
			struct in_addr in;
			inet_aton(ip, &in);

			if(arpheader->tpa == in.s_addr){
			uint8_t mac_sursa[6];
			get_interface_mac(m.interface, mac_sursa);

			uint8_t broadcast_dha[6];
			hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_dha);

			build_ethhdr(eth_hdr2, mac_sursa, eth_hdr->ether_shost, htons(ETHERTYPE_ARP));

			

			send_arp(arpheader->spa  , in.s_addr, eth_hdr2, m.interface, htons(ARPOP_REPLY));
			}

		} 
		}
		
		
		
		
		 //IP
else{
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		if(ip_hdr->ttl <= 1)
		{
			
			continue;
		}

		/*if( ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0)
		{
			
			continue;
		}*/


		unsigned short old_check = ip_hdr->check;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		if(old_check != ip_hdr->check){

			continue;
		}

		nod *r =  get_best_route(ip_hdr->daddr, r_table, size);

		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		// if pachet de tip request; else cu reply
		//if(arpheader->op == htons(ARPOP_REQUEST)){


		if(numar_cautari_in_arp_table == 0){
			queue_enq(q, &m);
			
			//generare header ethernet
			struct ether_header *eth_hdr2 = (struct ether_header*) (malloc (sizeof(struct ether_header)));
			uint8_t mac_sursa[6];
			get_interface_mac(r->interface, mac_sursa);
			uint8_t broadcast_dha[6];
			hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_dha);

			build_ethhdr(eth_hdr2, &mac_sursa, &broadcast_dha, htons(ETHERTYPE_ARP));

			char *ip = get_interface_ip(r->interface);  //saddr
			struct in_addr in;
			inet_aton(ip, &in);

			send_arp(r->next_hop, in.s_addr, eth_hdr2, r->interface, htons(ARPOP_REQUEST));  //trimitere request

			numar_cautari_in_arp_table = 1;

			
			
		}

		else{
				arp_entry *arp = get_arp_entry(ip_hdr->daddr, size_arp_table, arp_table);

				if(arp == NULL){                    // nu gasesc in arp_table ip ul si mac ul corespunzator, de care am nevoie
					queue_enq(q, &m);
			
					//generare header ethernet
					struct ether_header *eth_hdr2 = (struct ether_header*) (malloc (sizeof(struct ether_header)));
					uint8_t mac_sursa[6];
					get_interface_mac(r->interface, mac_sursa);
					uint8_t broadcast_dha[6];
					hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_dha);

					build_ethhdr(eth_hdr2, &mac_sursa, &broadcast_dha, htons(ETHERTYPE_ARP));

					char *ip = get_interface_ip(r->interface);  //saddr
					struct in_addr in;
					inet_aton(ip, &in);

					send_arp(r->next_hop, in.s_addr, eth_hdr2, r->interface, htons(ARPOP_REQUEST));  //trimitere request

					numar_cautari_in_arp_table = 1;


					//adaugare in arp_table a ip si mac
					/*arp_table[size_arp_table].ip = in.s_addr;
					memcpy(arp_table[size_arp_table].mac, broadcast_dha, 6);

					size_arp_table++;*/
				}

				else{                                                     // gasesc in arp table ceea ce imi trebuie
					arp_entry *a = get_arp_entry(r->next_hop, size_arp_table, arp_table);
					
					memcpy(eth_hdr->ether_dhost, a->mac, 6);
		
					get_interface_mac(r->interface, eth_hdr->ether_shost);
					send_packet(r->interface, &m);
				}
		}
		}
	}
		
	}
	

