import datetime

def dnsProcess(rawData, cache, seq, startTime, IDtrans, addr, debug_level):
    data = bytearray(rawData)
    datalen = len(data)
    ID = ( data[0] << 8) + data[1]
    QR = data[2] & 0x80             #judge if it's query or response
    OPCODE = data[2] & 0x78
    AA = data[2] & 0x04
    TC = data[2] & 0x02
    RD = data[2] & 0x01
    RA = data[3] & 0x80
    Z = data[3] & 0x70 
    RCODE = data[3] & 0x0F 
    
    #numbers of query and answer resources
    QDCOUNT = ( data[4] << 8) + data[5]
    ANCOUNT =  (data[6] << 8) + data[7]
    NSCOUNT = ( data[8] << 8) + data[9]
    ARCOUNT =  (data[10] << 8) + data[11]

    #get the list of queried name, and the pointer to the first ans resources
    ansPtr, name, QTYPE, QCLASS = getName(data, QDCOUNT)

    #initial value of the returned varience
    resFound = False
    response = bytearray()
    
    idx = -1
    if QR == 0 and QTYPE == 1:            # is query, get the name what to serch and give the result
        resFound, ip = cache.getItem(name)      # QTYPE

        if resFound == True:
            data[2] = data[2] | 0x80            #change the QR as response type 1
            if '0.0.0.0' == ip:
                                                #set the RCODE as 3: the name name referenced in the query does not exist.
                data[3] = data[3] & 0xF0                #set the RCODE segment into zero
                data[3] = data[3] | 0x03                # then filled it as ERROR

            else:                                   #query is for ip address
                                                    #construct and append the answer resources into the dnspacket
                ans = makeAns(ip, QTYPE)
                data += ans
                #modify the number of answer's resources
                if data[7] == 0xFF:
                    data[6] += 1
                    data[7] = 0
                else:
                    data[7] += 1
        else:
            interval = (datetime.datetime.now() - startTime).seconds
            if interval % 2 == 0:              # every two seconds flush IDtrans
                IDtrans = {}
            if IDtrans.keys().__len__() < 0xffff:
                idx = IDtrans.keys().__len__()
                IDtrans[idx] = ID
                data[0] = idx >> 8
                data[1] = idx % 256

    elif QR == 128:                                 # if QR=1 which means it is a response packet                                   
        if RCODE == 0:                              # check if it's correct
            if ID in IDtrans.keys():
                idx = IDtrans[ID]
                data[0] = idx >> 8
                data[1] = idx % 256
            ips = []                          #get the IP of the ANS from the packet
            ips = getAns(data, ansPtr, ANCOUNT)
            if len(ips) > 0:
                cache.addItem(name, ips[0][0], ips[0][1])

    response = bytes(data)
    
    if debug_level == 1:
        print ('%d:\t%s\tclient:%s:%d\t\t%s' %(seq, datetime.datetime.now(), addr[0], addr[1], name))
    if debug_level == 2:
        print ('%d:\t%s\tCLIENT %s:%d\t\t%s\t\tQTYPE %d\tQCLASS %d' %(seq, datetime.datetime.now(), addr[0], addr[1], name, QTYPE, QCLASS))
        if idx != -1:
            print('ID: {} -> {}'.format(ID, idx))
        print ('ID %d, QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA %d, Z %d, RCODE %d' %(ID, QR >> 7, OPCODE, AA, TC, RD, RA >> 7, Z, RCODE))
        print ('QDCOUNT %d, ANCOUNT %d, NSCOUNT %d, ARCOUNT %d' %(QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT))
        print ('RECV (%d bytes)' %(datalen))
        hexData = str(rawData.hex())
        for i, c in enumerate(hexData):
            if (i + 1) % 2 == 0:
                print('%c ' % c, end='')
            else:
                print('%c' % c, end='')
        print('')
    return resFound, response


#get the IP from the ANS resources of the packet
def getAns(data, ptr, ANCOUNT):
    ips = []

    while ANCOUNT > 0:                      #get IP from each resources
        #handling the name field
        if( data[ptr] & 0xC0) == 0xC0:      #the name is a pointer
            ptr += 2                        #skip 2 bytes
        else: #is a name
            while data[ptr] != 0:
                length = data[ptr]
                ptr += 1 + length    #ptr skip the name
            ptr += 1 #skip the len=0 segment

        #the TYPE field
        TYPE = (data[ptr] << 8) + data[ptr + 1]
        ptr+=4              #skip TYPE and CLASS field
        
        TTL = (data[ptr] << 24) + (data[ptr + 1] << 16) + (data[ptr + 2] << 8) + data[ptr + 3]
        ptr += 4            #skip TTL

        RDLENGTH  = (data[ptr] << 8) + data[ptr + 1]
        ptr += 2             #skip RDLENGTH

        if TYPE == 1:       #get an IPV4 address
            ip=''
            for i in range(4):
                ip +='.' + str(data[ptr + i])
            ips.append((ip[1:], TTL))       # add the ip address into ans
            
        ptr += RDLENGTH         #skip the RDLENGTH
        ANCOUNT-=1
    return ips


def makeAns(ip, QTYPE):
    ans = bytearray()
    ans += bytearray.fromhex('C00C')        #ptr to the domain name

    if QTYPE == 1:                          #ipv4 address, then the TYPE is A - 01
        ans.append(0)
        ans.append(1)
        RDLength = bytearray.fromhex('0004')
        RDATA = bytearray()
        ip = ip.split('.')
        for byte in ip:
            byte = int(byte)
            RDATA.append(byte)

    #the CLASS usually be 01
    ans.append(0)
    ans.append(1)

    TTL = hex(172800)           #two days' seconds
    fillLen = 10-len(TTL)       #fill the len to 4 bytes ('0x' in TTL[] should drop)
    zero = '0' * fillLen
    #change TTL into bytearray
    TTL = bytearray.fromhex(zero+TTL[2:])    
        
    ans += TTL + RDLength + RDATA
    return ans


def getName(data, QDCOUNT):
    ptr = 12
    name = ''

    while QDCOUNT > 0:
        name = ''
        while data[ptr]!= 0:
            name += '.'
            length = data[ptr]
            name += data[ptr + 1 : ptr + 1 + length].decode()
            ptr += 1 + length      

        ptr += 1                  #skip the end 0 flag
        name = name[1:]
        QDCOUNT -= 1

    QTYPE = (data[ptr] << 8) + data[ptr + 1]
    ptr += 2    #skip the query type
    QCLASS = (data[ptr] << 8) + data[ptr + 1]
    ptr += 2    #skip the query class

    return ptr, name, QTYPE, QCLASS
