import datetime
class Config:
    def __init__(self, dnsServerIp, debug_level):
        self.dnsServerIp  = dnsServerIp
        self.debug_level = debug_level
        self.seq = 0
        self.IDtrans = {}
        self.startTime = datetime.datetime.now()
        self.file = open('log.txt', 'a')

