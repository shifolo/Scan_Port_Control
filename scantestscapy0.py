#!/usr/bin/python3

import nmap
from scapy.all import *
from scapy.all import IP, TCP, ICMP, sr1

def scan_ports_with_nmap(target_ip, start_port, end_port):
    nm = nmap.PortScanner()
    # Ajout d'arguments pour une détection de service plus précise
    scan_arguments = f'-Pn -sS -p {start_port}-{end_port} -sV --version-intensity 5 --script banner'
    nm.scan(target_ip, arguments=scan_arguments)
    
    open_ports = []
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service_name = nm[host][proto][port].get('name', 'unknown')
                service_version = nm[host][proto][port].get('version', 'unknown')
                service_product = nm[host][proto][port].get('product', 'unknown')
                service_extrainfo = nm[host][proto][port].get('extrainfo', 'unknown')
                if state == 'open':
                    open_ports.append((port, 'Open', service_name, service_version, service_product, service_extrainfo))
                elif state == 'closed':
                    open_ports.append((port, 'Closed', service_name, service_version, service_product, service_extrainfo))
                elif state == 'filtered':
                    open_ports.append((port, 'Filtered', service_name, service_version, service_product, service_extrainfo))
    
    return open_ports

def scan_ports_with_scapy(target_ip, open_ports):
    for port_info in open_ports:
        port = port_info[0]
        state = port_info[1]
        if state == "Open":
            # Crée un paquet TCP SYN pour le port spécifié
            tcp_syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            # Envoie le paquet et capture la réponse
            response = sr1(tcp_syn_packet, timeout=2, verbose=0)

            if response:
                if response.haslayer(TCP):
                    if response[TCP].flags == "SA":  # SYN-ACK, port ouvert
                        # Envoie un paquet TCP ACK pour compléter le handshake et récupérer des informations
                        tcp_ack_packet = IP(dst=target_ip) / TCP(dport=port, flags="A", ack=(response[TCP].seq + 1))
                        sr1(tcp_ack_packet, timeout=2, verbose=0)
                    elif response[TCP].flags == "RA":  # RST-ACK, port fermé
                        port_info[1] = "Closed"
                elif response.haslayer(ICMP):
                    if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        port_info[1] = "Filtered"

if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP cible: ")
    start_port = int(input("Entrez le port de début de la plage: "))
    end_port = int(input("Entrez le port de fin de la plage: "))

    open_ports = scan_ports_with_nmap(target_ip, start_port, end_port)

    if open_ports:
        print(f"\nPorts ouverts sur {target_ip}:")
        scan_ports_with_scapy(target_ip, open_ports)
        for port_info in open_ports:
            port = port_info[0]
            status = port_info[1]
            service_name = port_info[2]
            service_version = port_info[3]
            service_product = port_info[4]
            service_extrainfo = port_info[5]
            print(f"- {port}/TCP {status}, Service: {service_name}, Version: {service_version}, Produit: {service_product}, Info Supplémentaire: {service_extrainfo}")
    else:
        print(f"\nAucun port ouvert trouvé sur {target_ip} dans la plage spécifiée.")
