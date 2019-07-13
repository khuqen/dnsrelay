# dns 10.3.9.5
import datetime
from Cache import Cache
from Config import Config
from dnsProcess import dnsProcess
import argparse
import socket
import socketserver

parser = argparse.ArgumentParser(description='DNSRELAY, Version 1.0 Build: July 10 2019')
parser.add_argument('-d', help='Set debugging information level to 1', action='store_true')
parser.add_argument('-dd', help='Set debugging information level to 2', action='store_true')
parser.add_argument('-ip', help='Specify the domain name server address')
parser.add_argument('-f', help='Specify the configuration file')
args = parser.parse_args()

debug_level = 0
dnsIpAddr = '10.3.9.5'

filename = 'dnsrelay.txt'
if args.d:
    debug_level = 1
if args.dd:
    debug_level = 2
if args.ip:
    dnsIpAddr = args.ip
if args.f:
    filename = args.f


class Myhandle(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0]     
        resFound, response = dnsProcess(data, cache, config.seq, config.startTime, config.IDtrans, self.client_address, config.debug_level, config.file)
        config.seq += 1
        if resFound:
            self.request[1].sendto(response, self.client_address)
        else:
            udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udpSocket.sendto(response, (config.dnsServerIp, 53))
            udpSocket.settimeout(1)
            retransmitFlag = False
            try:
                t_data, addr= udpSocket.recvfrom(1024)
                _, response = dnsProcess(t_data, cache, config.seq, config.startTime, config.IDtrans, addr, config.debug_level, config.file)
                config.seq += 1
                self.request[1].sendto(response, self.client_address)
            except socket.timeout:
                if retransmitFlag == False:
                    udpSocket.sendto(response, (config.dnsServerIp, 53))
                    retransmitFlag = True

if __name__ == "__main__":

    cache = Cache(filename)
    print('Load file from \'{}\' successfully'.format(filename))
    config = Config(dnsIpAddr, debug_level)
    print('Connect successfully to dns server {}.'.format(dnsIpAddr))
    DnsServer = socketserver.ThreadingUDPServer(('', 53), Myhandle)
    DnsServer.serve_forever()
    config.file.close()