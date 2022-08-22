from typing import get_args
from scapy.all import *
from argparse import ArgumentParser

# TTL per defecte
def numero_ttl(ttl):
    if ttl > 0 and ttl <= 64:
        return "Linux"
    elif ttl > 64 and ttl <= 128:
        return "Windows"

# Objecte Escanner
class EscannerXarxa:
    def __init__(self, host):
        for host in hosts:
            self.host = host
            self.actius = {}
            self.crear_dif_paquet()
            self.enviar_dif_paquet()
            self.get_equips_actius()
            self.get_tipus_equip()
            self.print_actius()

    # Creació paquet difusió
    def crear_dif_paquet(self):
        capa1 = Ether(dst = "ff:ff:ff:ff:ff:ff") #Broadcast
        capa2 = ARP(pdst = self.host)
        paquet = capa1/capa2
        self.paquet = paquet

    # Enviament paquets
    def enviar_dif_paquet(self):
        resposta, no_resposta = srp(self.paquet, timeout=120, verbose = False)
        self.resposta = resposta if resposta else print("No hi ha cap equip actiu")
    
    # Equips actius
    def get_equips_actius(self):
        for enviats, rebuts in self.resposta:
            self.actius[rebuts.psrc] = rebuts.hwsrc
        
    # Tipus de maquina segons TTL
    def get_tipus_equip(self):
        for ip in self.actius.keys():
            icmp = ICMP(type = 8, code = 0)
            paquet_ip = IP(src = "192.168.1.136", dst = ip)
            paquet_ping = paquet_ip/icmp
            resposta_ping = sr1(paquet_ping, timeout = 30, verbose = False)
            self.actius[ip] = numero_ttl(resposta_ping.ttl) if resposta_ping else "No es possible determinar el sistema"

    # Presentació resultats
    def print_actius(self):
        print(self.actius)

# Parametres per consola
def get_args():
    parser = ArgumentParser(description= "Eina d'analisis de xarxa local")
    parser.add_argument("--h", dest = "hosts", nargs = "+", help="Hosts a escanejar")
    arg = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return arg.hosts

if __name__ == '__main__':
    hosts = get_args() # Introduccio parametres 
    EscannerXarxa(hosts)
