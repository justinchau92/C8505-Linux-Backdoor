# C8505-Linux-Backdoor

## Backdoor.py 
This is a backdoor program ran on the victim computer.
It works with client.py where it is place on a seperate computer.
Receives commands from client.py and executes it on the workstation
and replies back to the client with information

## Client.py
Client program that works with backdoor.py
Connects with backdoor placed on a seperate workstation. Sends
commands to backdoor to gain information of the backdoor workstation.
