#include "queue.h"
#include "skel.h"

#define MAX_SIZE 100000


void incr_checksum(struct iphdr *iph, uint16_t* old_value, uint16_t new_value){

	memcpy(old_value, &iph->ttl, 2);
	iph->ttl--;
	memcpy(&new_value, &iph->ttl, 2);

	iph->check = iph->check + *old_value + ~(new_value);
}

int get_best_route(struct route_table_entry *rtable, int rtable_len, uint32_t dest_ip)
{
	int idx = -1;

	for (int i = 0; i < rtable_len; i++)
	{
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix)
		{
			if (idx == -1)
				idx = i;
			else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask))
				idx = i;
		}
	}

	return idx;
}

struct arp_entry *get_arp_entry(uint32_t dest_ip, struct arp_entry *cache, int len_cache)
{
	for (size_t i = 0; i < len_cache; i++)
	{
		if (dest_ip == cache[i].ip)
			return &cache[i];
	}

	return NULL;
}

//sortam crescator dupa prefix si descrescator dupa masca
int comparator(const void *a, const void *b)
{
	struct route_table_entry *r1 = (struct route_table_entry *)a;
	struct route_table_entry *r2 = (struct route_table_entry *)b;

	if (ntohl(r1->prefix) < ntohl(r2->prefix))
	{
		return -1;
	}
	else if (ntohl(r1->prefix) > ntohl(r2->prefix))
	{
		return 1;
	}else 
	{
		if (ntohl(r2->mask) > ntohl(r1->mask))
		{
			return 1;
		
		}else if (ntohl(r2->mask) < ntohl(r1->mask))
		{
			return -1;
		}
		else
		{
			return -1;
		}
	}
	
}

int binary_search(struct route_table_entry *rtable, uint32_t dest_ip, int left, int right)
{
	if (right >= left)
	{
		int mid = (left + right) / 2;

		if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix)
		{
			uint32_t prefix = rtable[mid].prefix;
			if (mid == 0)
			{
				return 0;
			}
			else
			{
				while (rtable[mid].prefix == prefix)
				{
					mid = mid -1;
				}
				return mid + 1;
				
			}
		}
		else
		{
			if (ntohl(dest_ip) < ntohl(rtable[mid].prefix))
			{
				return binary_search(rtable, dest_ip, left, mid - 1);
			}
			else if (ntohl(dest_ip) > ntohl(rtable[mid].prefix))
			{
				return binary_search(rtable, dest_ip, mid + 1, right);
			}
		}
	}
	
	return -1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct arp_entry *cache = (struct arp_entry *)calloc(MAX_SIZE, sizeof(struct arp_entry));
	int crt_pos_in_cache = 0;

	queue q = queue_create();

	struct route_table_entry *rtable = (struct route_table_entry *)calloc(MAX_SIZE, sizeof(struct route_table_entry));
	int rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator);

	while (1)
	{

		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		if (m.len < sizeof(struct ether_header))
		{
			continue;
		}

		struct ether_header *eth = (struct ether_header *)m.payload;

		struct arp_header *arph;
		struct iphdr *iph;
		struct icmphdr *icmph;
		struct route_table_entry *best_route;

		uint16_t crt_checksum = 0;

		// extrag adresa mea ip
		uint32_t ip;
		inet_aton(get_interface_ip(m.interface), (struct in_addr *)&ip);

		// extrag adresa mea mac
		uint8_t mac[ETH_ALEN];
		get_interface_mac(m.interface, mac);


		//............ARP............

		if (ntohs(eth->ether_type) == (uint16_t)0x0806)
		{
			arph = (struct arp_header *)(m.payload + sizeof(struct ether_header));
			// inet_aton(get_interface_ip(m.interface), (struct in_addr *)&ip);

			if ((ntohs(arph->op) == 1) && (arph->tpa == ip))
			{ // request
				arph->op = htons((uint16_t)2);

				memcpy(eth->ether_dhost, arph->sha, ETH_ALEN);
				memcpy(arph->tha, arph->sha, ETH_ALEN);
				arph->tpa = arph->spa;

				arph->spa = ip;
				memcpy(arph->sha, mac, ETH_ALEN);
				memcpy(eth->ether_shost, mac, ETH_ALEN);

				send_packet(&m);
				continue;
			}

			if (ntohs(arph->op) == 2)
			{ // reply
				// adaug in cache ip, mac
				// scot pachetul din coada si ii asociez mac ul

				if (queue_empty(q))
				{
					continue;
				}
				cache[crt_pos_in_cache].ip = arph->spa;
				memcpy(cache[crt_pos_in_cache].mac, arph->sha, ETH_ALEN);
				crt_pos_in_cache++;

				packet *p = (packet *)queue_deq(q);
				struct ether_header *p_eth = (struct ether_header *)p->payload;
				memcpy(p_eth->ether_dhost, arph->sha, ETH_ALEN);

				send_packet(p);
				
				continue;
			}
		}

		//.................IPv4..............


		if (ntohs(eth->ether_type) == (uint16_t)0x0800)
		{
			iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			if ((icmph != NULL) && (iph->daddr == ip) && (icmph->type == 8) && (icmph->code == 0))
			{
				// inseamna ca e pt mn pachet icmp si trb sa trimit inapoi la sursa pachet icmp reply

				icmph->type = 0; // fac icmp de tip reply

				// actualizez sursa si dest in headerul ip
				iph->daddr = iph->saddr;
				iph->saddr = ip;

				icmph->checksum = 0;
				icmph->checksum = icmp_checksum((uint16_t *)icmph, sizeof(struct icmphdr));

				// actualizez sursa si dest in headerul ethernet
				memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
				memcpy(eth->ether_shost, mac, ETH_ALEN);

				send_packet(&m);
				continue;
			}

			uint16_t checksum_copy = iph->check;
			iph->check = 0;
			crt_checksum = ip_checksum((void *)iph, sizeof(struct iphdr));

			if (checksum_copy != crt_checksum)
			{
				continue;
			}
			if (iph->ttl == 0 || iph->ttl == 1) //campul ttl a expirat -> Time exceeded
			{
				memmove(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + 4, m.payload + sizeof(struct ether_header) + sizeof(struct iphdr), 4);
				icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
				memcpy(eth->ether_shost, mac, ETH_ALEN);

				iph->daddr = iph->saddr;
				iph->saddr = ip;
				iph->protocol = 1;
				iph->tot_len = htons(ntohs(iph->tot_len) + 4);
				m.len += 4;

				iph->check = 0;
				ip_checksum((void *)iph, sizeof(struct iphdr));

				icmph->code = 0;
				icmph->type = 11;

				icmph->checksum = 0;
				icmph->checksum = icmp_checksum((uint16_t *)icmph, sizeof(struct icmphdr));

				send_packet(&m);

				continue;
			}

			iph->ttl--;

			int index = get_best_route(rtable, rtable_len, iph->daddr);
			//int index = binary_search(rtable, iph->daddr, 0, rtable_len - 1);


			if (index == -1)
			{
				best_route = NULL;
			}
			else
			{
				best_route = &rtable[index];
			}

			if (best_route == NULL) //nu exista ruta de la mine la destinatie  -> trimit Destination unreacheable
			{
				memmove(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + 4, m.payload + sizeof(struct ether_header) + sizeof(struct iphdr), 4);
				icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
				memcpy(eth->ether_shost, mac, ETH_ALEN);

				iph->daddr = iph->saddr;
				iph->saddr = ip;
				iph->protocol = 1;
				iph->tot_len = htons(ntohs(iph->tot_len) + 4);
				m.len += 4;

				iph->check = 0;
				ip_checksum((void *)iph, sizeof(struct iphdr));

				icmph->code = 0;
				icmph->type = 3;

				icmph->checksum = 0;
				icmph->checksum = icmp_checksum((uint16_t *)icmph, sizeof(struct icmphdr));

				send_packet(&m);

				continue;
			}

			iph->check = 0;
			iph->check = ip_checksum((void *)iph, sizeof(struct iphdr));
			//incr_checksum(iph, (uint16_t *) &iph->ttl, ((uint16_t)(iph->ttl - 1) << 8 | (uint16_t)iph->protocol));

			struct arp_entry *cache_info = get_arp_entry(best_route->next_hop, cache, crt_pos_in_cache);

			m.interface = best_route->interface;
			get_interface_mac(m.interface, mac);
			memcpy(eth->ether_shost, mac, ETH_ALEN);

			if (cache_info == NULL)//mac-ul cautat nu se afla in cache
			{
				// pun in coada pachet cu cerere ARP
				memcpy(eth->ether_shost, mac, ETH_ALEN);


				packet copy_p;
				copy_p.interface = m.interface;
				copy_p.len = m.len;
				memcpy(copy_p.payload, m.payload, sizeof(m.payload));

				queue_enq(q, (void *)&copy_p);
			
				// trb sa l fac arp
				packet arp_p;
				arp_p.interface = m.interface;
				arp_p.len = sizeof(struct ether_header) + sizeof(struct arp_header);

				struct ether_header *eth_p;
				eth_p = (struct ether_header *)arp_p.payload;

				memcpy(eth_p->ether_shost, mac, ETH_ALEN);

				uint8_t addr[ETH_ALEN];
				hwaddr_aton("FF:FF:FF:FF:FF:FF", addr);

				memcpy(eth_p->ether_dhost, addr, ETH_ALEN);

				eth_p->ether_type = htons(0x0806);

				struct arp_header *arp_h = (struct arp_header *)(arp_p.payload + sizeof(struct ether_header));

				arp_h->htype = htons(1);
				arp_h->ptype = htons((uint16_t)0x0800);
				arp_h->hlen = (uint8_t)6;
				arp_h->plen = (uint8_t)4;
				arp_h->op = htons((uint16_t)1); // il facem de tip arp request 

				memcpy(arp_h->sha, mac, ETH_ALEN);
				uint32_t new_ip;
				inet_aton(get_interface_ip(m.interface), (struct in_addr *)&new_ip);
				arp_h->spa = new_ip;

				memcpy(arp_h->tha, addr, ETH_ALEN);
				arp_h->tpa = best_route->next_hop;

				send_packet(&arp_p);
				
				continue;
			}

			// am gasit mac ul cautat in cache
			memcpy(eth->ether_shost, mac, ETH_ALEN);
			memcpy(eth->ether_dhost, cache_info->mac, ETH_ALEN);

			send_packet(&m);
			continue;
		}
	}
}
