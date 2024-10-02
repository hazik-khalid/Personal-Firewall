import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)


def main():
 while True:
    print(s.recvfrom(65565))
    raw_data, addr = s.recvfrom(65535)
    eth = ethernet(raw_data)
    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],
    eth[2]))
    
main()