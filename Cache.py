import sys
import redis
class Cache:
    def __init__(self, path):
        self.r = redis.Redis()
        f = open(path, 'r')
        cnt = 0
        for line in f:
            if not line.isspace():
                s = line.split()
                cnt += 1
                self.r.set(s[1], s[0])
        f.close()
        print('All {} static names initially.'.format(cnt))

    def getItem(self, name):
        if self.r.exists(name):
            res = self.r.get(name)
            return True, res.decode()
        else:
            return False, ''

    def addItem(self, name, ip, ttl):
        self.r.set(name, ip, ex=ttl)
