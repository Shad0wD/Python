from scapy.all import *
#from netifaces import *
import random
import sys
import time
from io import StringIO

# Storm_ControlBroadcast: Envoie beaucoup de paquet avec une adresse de destination MULTICAST
# Storm_ControlMulticast: Envoie beaucoup de paquet avec une adresse de destination BROADCAST
# IPSG_Ping_Random_IP : Ping avec différentes IP adresse
# DAI_Test_Different_IP_MAC : Envoie des paquets ARP avec des adresses MAC random - Gratuitous ARP avec MAC et IP différente de celle vu par DHCP snooping
# DAI_RateARP : Test Rate limite ARP => Error Disable (Fonctionne meme si le port est trusted)
# DHCPSnooping_Rogue : Test de Rogue DHCP
# DHCPSnooping_RateLimit : Envoie d'un grand nombre de requete DHCP => err_disable

#Envoie nbMac ping avec des adresses MAC source aléatoires.
#Permet de tester entre autre les fonctionnalité de Port-Security et de creer une violation de 802.1X
def Ping_Random_MACSender (interface, nbMac=5, MAC_Entreprise="00:00:0E"):
    j=0
    while (j < nbMac):
        MACsource=MAC_Entreprise
        i = 0
        while (i < 3) :
            a=random.randint(0,16)
            print(a)
            MACsource = MACsource + ":" + str(a)
            i += 1

        Paquet = Ether(dst="ff:ff:ff:ff:ff:ff",src=MACsource)/IP(dst="192.168.1.4",src="192.168.1.100")/ICMP(id=j+1,seq=j+2)/"Voila"
        sendp(Paquet, iface=interface)
        j += 1
        print(j)

#Sniff l'interface définit et retourne le premier paquet ARP que le processus voit (Le paquet peut être une réponse, une requete ou un gratuitous ARP)
def Ecoute_1_Requete_ARP(interface="Intel(R) 82574L Gigabit Network Connection"):
    ## Ecoute les uniquement les paquet ARP sur l'interface spécifié. On arrete l'écoute quand on en a un et le paquet est retourné dans une variable.
    paquet = sniff(count=1, filter="arp",iface=interface)
    print("#1----------------------------")
    print(paquet[0].show())
    return paquet

#Envoie une réponse ARP pour une l'IP_spoofé avec une adresse IP et MAC différente de l'interface (celles de la machine usurpée)
def réponse_ARP (interface, IP_spoofé, MAC_demandeur, IP_demandeur):
    Paquet = Ether(dst=MAC_demandeur)/ARP(op=2,pdst=IP_demandeur,hwdst=MAC_demandeur,psrc=IP_spoofé)
    sendp(Paquet, iface=interface)

#Ecoute les paquets ARP et répond à toutes les requetes ARP avec l'adresse MAC de son interface.
#Permet notamment de tester la fonctionnalité de DAI. (La fonction va surement répondre à des requete ARP avec des IP qui ne sont pas l'IP de la machine)
def spoofing_ARP_segment(interface):
    i=0
    while True :
        print("En écoute ARP #" + str(i))
        i += 1
        Lpkt = Ecoute_1_Requete_ARP()
        arp = Lpkt[0]
        print("#2-----------------------------")
        if (arp.op == 1) :
            print("Try IP spoof : " + str(arp[ARP].hwsrc) + " at " + str(arp[ARP].psrc))
            réponse_ARP (interface, str(arp[ARP].pdst), str(arp[ARP].hwsrc), str(arp[ARP].psrc))
        else:
            print("Ce n'était pas une requete ARP")

#Envoie une gratuitous ARP avec une l'adresse IP spécifiée. (Ca ne va pas redéfinir les résolutions ARP des hôtes car les hôtes configuré avec la même adresse vont re-répondre avec un gratuitous ARP).
def GratuitousARP(interface, IPGratuitous="192.168.1.100"):
    paquet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", psrc=IPGratuitous, pdst=IPGratuitous)
    sendp(paquet, iface=interface)

#Envoie un gratuitous ARP avec une IP spécifique.
def GratuitousARP_RandomMAC(Interface,IPGratuitous="192.168.1.101"):
    MACsource = "00:00:0E"
    i = 0
    while (i < 3):
        a = random.randint(0, 16)
        MACsource = MACsource + ":" + str(a)
        i += 1
    paquet = Ether(dst="ff:ff:ff:ff:ff:ff", src=MACsource)/ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=MACsource, psrc=IPGratuitous, pdst=IPGratuitous)
    sendp(paquet, iface=Interface)

# Permet d'obtenir le nom de l'interface en fonction de l'adresse IP de l'interface.
def get_interface(IP="192.168.1.3") :
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    show_interfaces()
    sys.stdout = old_stdout
    ListInterface = result.getvalue()
    ArrayIface = ListInterface.split()
    i = ArrayIface.index(IP)
    Interface = ArrayIface[5] + " " + ArrayIface[6] + " " + ArrayIface[7] + " " + ArrayIface[8] + " " + ArrayIface[9]
    MAC_Interface = ArrayIface[11]
    print("L'interface sélectionné est " + Interface + " qui l'adresse MAC : " + MAC_Interface)
    return Interface, MAC_Interface, IP


#Créer une requete DHCP
#Permet de tester la limite du nombre de DHCP requete par seconde.
def DHCP_requete(nbRequeteDHCP, nom_Interface, mac_interface) :
    Lpaquet = sniff (offline="Z:\Mes documents\Securité sur les ports\DHCP.pcapng")
    paquet = Lpaquet[8]
    print(paquet[DHCP].options[1])
    print(paquet[DHCP].options)
    print(type(paquet[DHCP].options))
    paquet[Ether].src = mac_interface
    paquet[Ether].dst="04:6c:9d:f1:35:40"
    mac_interface = "b'" + mac_interface + ":00:00:00:00:00:00:00:00:00:00'"
    mac_decimal=mac_interface.replace(":",r"\x")
    print(mac_decimal)
    paquet[BOOTP].chaddr = mac_decimal
    i=0
    while i<nbRequeteDHCP :
        i+=1
        sendp(paquet, iface=nom_Interface)

def requete_ARP(interface, IP_demandée):
    Paquet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,pdst=IP_demandée, hwsrc = "b8:6b:23:52:23:0e")
    sendp(Paquet, iface=interface)

# -----------------------------------

def Storm_ControlBroadcast(interface):
    nbPaquet=0
    while nbPaquet < 10000:
        nbPaquet += 1
        requete_ARP(interface, "192.168.1.1")

def Storm_ControlMultiCast(interface):
    nbPaquet=0
    while nbPaquet < 10000:
        nbPaquet += 1
        Paquet = Ether(dst="01:00:5e:00:00:02")/ARP(op=1,pdst=IP_demandée, hwsrc = "b8:6b:23:52:23:0e")
        sendp(Paquet, iface=interface)

def IPSG_Ping_Random_IP(interface):
    nbPaquet = 0
    while nbPaquet < 10000:
        nbPaquet += 1
        IP_Ping = random.randint(1, 253) + "." + random.randint(1, 253) + "." + random.randint(1, 253) + "." + random.randint(1, 253)
        Paquet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=IP_Ping, src="192.168.1.100") / ICMP(id=j + 1, seq=j + 2) / "Voila"
        sendp(Paquet, iface=interface)

def DAI_Test_Different_IP_MAC(interface) :
    nbPaquet = 0
    while nbPaquet < 4:
        nbPaquet += 1
        GratuitousARP_RandomMAC(interface, IP = "192.160.1.2")

def DAI_RateARP(interface) :
    nbPaquet = 0
    while nbPaquet < 10:
        nbPaquet += 1
        Paquet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,pdst="192.168.1.4")
        sendp(Paquet, iface=interface)

def DHCPSnooping_RateLimit(nbRequete, nom_Interface, mac_interface) :
    Lpaquet = sniff (offline="Z:\Mes documents\Securité sur les ports\DHCP.pcapng")
    paquet = Lpaquet[8]
    paquet[Ether].dst="ff:ff:ff:ff:ff:ff"
    # paquet[Ether].src = mac_interface
    # paquet[IP].len=252
    # paquet[UDP].len=''
    # paquet[UDP].chksum=''
    # a = mac_interface.lower()
    # a = a.split(':')
    # print(a)
    # b = []
    # for i in a:
    #     b.append(chr(int(i, 16)))
    # mac_hex = "".join(b)
    # paquet[BOOTP].chaddr = mac_hex
    # paquet[DHCP].options =[("message-type","discover"),"end"]
    i=0
    while i<nbRequete :
        i+=1
        sendp(paquet, iface=nom_Interface)

def DHCPSnooping_PaquetServeur(nbRequete, nom_Interface, mac_interface) :
    Lpaquet = sniff (offline="Z:\Mes documents\Securité sur les ports\DHCP.pcapng")
    paquet = Lpaquet[9]
    paquet[Ether].dst="ff:ff:ff:ff:ff:ff"
    i=0
    while i<nbRequete :
        i+=1
        sendp(paquet, iface=nom_Interface)

nom_Interface, mac_interface, IP_interface = get_interface("192.168.1.3")
debut = time.time()
# DHCPSnooping_RateLimit(10, nom_Interface, mac_interface)
DHCPSnooping_PaquetServeur(10, nom_Interface, mac_interface)
# DAI_RateARP(nom_Interface)
# DAI_Test_Different_IP_MAC(nom_Interface)
# IPSG_Ping_Random_IP(nom_Interface)
# Storm_ControlMultiCast(nom_Interface)
# Storm_ControlBroadcast(nom_Interface)
print ("--- %s seconds ---" % (time.time() - debut))
