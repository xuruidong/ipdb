import socket
import struct

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))




def create_ipdb(data):    
    #fill the ip segments
    tmp_dict = {}
    for d in data:
        tmp_dict[ip2int(d[0])] = d
        
    print (tmp_dict)
    print (tmp_dict.keys())
    print (sorted(tmp_dict.keys()))
    
    
    complement_list = []
    last_end = -1
    for k in sorted(tmp_dict.keys()):
        if (k <= last_end):
            print ("error")
            return 1
        
        end = ip2int(tmp_dict[k][1])
        if ( end < k ):
            print ("error: end < start")
            print (k, end)
            return 2
        
        if (end > 0xffffffff):
            print ("error: end > 0xffffffff")
            return 3
        
        if (k > last_end + 1):
            # fill  last_end+1 ~ k-1,
            start_str = int2ip(last_end + 1)
            end_str = int2ip(k - 1)
            complement_list.append((start_str, end_str,"" , 1))
            tmp_dict[last_end + 1] = (start_str, end_str,"" , 1)
            
        last_end = end
    
    if (last_end < 0xffffffff):
        print("add last")
        start_str = int2ip(last_end + 1)
        end_str = int2ip(0xffffffff)
        complement_list.append((start_str, end_str,"" , 1))
        tmp_dict[last_end + 1] = (start_str, end_str,"" , 1)        
        
    print (data + complement_list)
    print (len(data + complement_list))
    print (len(tmp_dict))
    
    #create file
    seg_index = b""
    seg_ip_seg = b""
    seg_content = b""
    last_i = 0
    ip_seg_len = len(data + complement_list)*9
    
    print ("ip_seg_len=%d"%ip_seg_len)
    next_content_addr = ip_seg_len
    content_dict = {}
    for k in sorted(tmp_dict.keys()):
        
        for i in range(last_i,65537):
            
            if(k <= (i*65536)):
                #find content
                if(len(tmp_dict[k]) == 4  and tmp_dict[k][3] == 1):
                    print ("p %d, 111"%k)
                    seg_ip_seg += struct.pack("!L", k) + struct.pack("!L", ip_seg_len) + struct.pack("B", 1)
                else:
                    print ("p %d, 22222222"%k)
                    if (tmp_dict[k][2] not in content_dict.keys()):
                        seg_content += ( struct.pack("!L", len(tmp_dict[k][2])) + tmp_dict[k][2].encode())
                        content_dict[tmp_dict[k][2]] = (next_content_addr, len(tmp_dict[k][2]))
                        seg_ip_seg += (struct.pack("!L", k) + struct.pack("!L", next_content_addr) + struct.pack("B", 0))
                        next_content_addr += ( 4 + len(tmp_dict[k][2]) )
                    else:
                        cont_addr = content_dict[tmp_dict[k][2]][0]
                        seg_ip_seg += (struct.pack("!L", k) + struct.pack("!L", cont_addr) + struct.pack("B", 0))
                
                
                break
            last_i = i
            
    current_seg_addr = 0
    last_seg_addr = 0
    index2segaddr = {}     
    
    print (sorted(tmp_dict.keys()))
    iter_k = iter(sorted(tmp_dict.keys()))
    #index2segaddr[0] = 0
    last_i = -1
    #flag_first = 1
    current_k = 0
    for i in range(0,65536):
        index2segaddr[i] = last_seg_addr
        seg_index += struct.pack("!L", last_seg_addr)  
        if (i*65536 < current_k):
            continue
        else:
            if (i>1):
                if ((i-1)*65536 < current_k):
                    current_seg_addr += 9
            last_seg_addr = current_seg_addr
            index2segaddr[i] = last_seg_addr
        for k in iter_k:
            print ("============process %d"%k)
            if(k <= i*65536):
                current_seg_addr += 9
                print ("add 9 @ %d"%k)
                continue
                '''
            elif(k <= (i+1)*65536):
                current_seg_addr += 9
                print ("add 9 @ %d"%k)
                continue
                '''
            else:
                #current_seg_addr += 9
                print ("break %d"%k)
                current_k = k
                
                break
    '''
    
    it_range = iter(range(0,65536))
    for k in sorted(tmp_dict.keys()):
        for i in it_range:
            if(k <= i*65536):
                current_seg_addr += 9
                index2segaddr[i] = last_seg_addr
                break
            index2segaddr[i] = last_seg_addr
    '''    
    print (index2segaddr[0])
    print (index2segaddr[1])
    print (index2segaddr[0x7f00])
    print (index2segaddr[0x7f01])
    print (index2segaddr[0xC0A8])
    print (index2segaddr[0xC800])
    print (index2segaddr[0xC801])
    
    #print (seg_index)
    print (seg_ip_seg)
    print (seg_content)
    ipseg_len = struct.pack("!L", len(seg_ip_seg))
    
    with open("ipdb", "wb") as f:
        f.write(struct.pack("!L", 4+65536*4+4+len(seg_ip_seg)+len(seg_content)))
        f.write(seg_index)
        f.write(struct.pack("!L", len(seg_ip_seg)))
        f.write(seg_ip_seg)
        f.write(seg_content)
        
                
 
def ipdb_find(ipdb_file, ip_str):
    ipdb_content = None
    with open(ipdb_file, "rb") as f:
        ipdb_content = f.read()
    
    length = struct.unpack("!L", ipdb_content[:4])[0]
    print (length)
    dst_ip = ip2int(ip_str)
    ind = int(dst_ip/65536)
    print (ind)
    ip_seg_addr = struct.unpack("!L", ipdb_content[4+ind*4:4+ind*4+4])[0]
    print (ip_seg_addr)
    ip_seg_len = struct.unpack("!L", ipdb_content[4+65536*4:4+65536*4+4])[0]
    print ("ip_seg_len=%d   ???"%ip_seg_len)
    
    ip_seg_offset = 4+4*65536+4
    while True:
        if (ip_seg_addr > ip_seg_len):
            print ("ip_seg_addr error, %d"%(ip_seg_addr))
            break
        ipaddr_start = struct.unpack("!L", ipdb_content[ip_seg_offset + ip_seg_addr : ip_seg_offset + ip_seg_addr + 4])[0]
        print ("ipaddr_start=%d, dst_ip=%d"%(ipaddr_start, dst_ip))
        if (ipaddr_start >= dst_ip):
            if (ipaddr_start > dst_ip):
                c = ipdb_content[ip_seg_offset + ip_seg_addr - 9 : ip_seg_offset + ip_seg_addr]
            else:
                c = ipdb_content[ip_seg_offset + ip_seg_addr : ip_seg_offset + ip_seg_addr + 9]
                
            flag = struct.unpack("B", c[8: 9])[0]
            if(flag == 1):
                return (1, None) 
            
            content_addr = struct.unpack("!L", c[4: 8])[0]
            #read content
            content_len = struct.unpack("!L", ipdb_content[ip_seg_offset + content_addr : ip_seg_offset + content_addr + 4])[0]
            return (0, ipdb_content[ip_seg_offset + content_addr + 4 : ip_seg_offset + content_addr + 4 + content_len])
        '''        
        if (ipaddr_start > dst_ip):
            flag = struct.unpack("B", ipdb_content[ip_seg_offset + ip_seg_addr - 1: ip_seg_offset + ip_seg_addr])[0]
            print ("flag=%d"%flag)
            if(flag == 1):
                return (1, None)
            content_addr = struct.unpack("!L", ipdb_content[4+4*65536+4+ip_seg_addr-5: 4+4*65536+4+ip_seg_addr-1])[0]
            #read content
            content_len = struct.unpack("!L", ipdb_content[4+4*65536+4+content_addr: 4+4*65536+4+content_addr + 4])[0]
            return (0, content_len)
        elif (ipaddr_start == dst_ip):
            print ("===========ipaddr_start == dst_ip")
            flag = struct.unpack("B", ipdb_content[ip_seg_offset + ip_seg_addr + 8 : ip_seg_offset + ip_seg_addr + 9])[0]
            print ("flag=%d"%flag)
            print (flag)
            if(flag == 1):
                return (1, None)
            content_addr = struct.unpack("!L", ipdb_content[ip_seg_offset + ip_seg_addr + 4 : ip_seg_offset + ip_seg_addr + 8])[0]
            print ("content_addr=%d"%content_addr)
            #read content
            print (ipdb_content[ip_seg_offset + content_addr : ip_seg_offset + content_addr + 4])
            content_len = struct.unpack("!L", ipdb_content[ip_seg_offset + content_addr : ip_seg_offset + content_addr + 4])[0]
            return (0, content_len)            
            '''
        ip_seg_addr += 9
        if (ip_seg_addr > ip_seg_len - 9):
            print (">>>>")
            break
 
def ipdb_load(ipdb_file:str):
    ret_val = []
    ipdb_content = None
    with open(ipdb_file, "rb") as f:
        ipdb_content = f.read()
    
    length = struct.unpack("!L", ipdb_content[:4])[0]
    
    ip_segs_len = struct.unpack("!L", ipdb_content[4 + 65536 * 4 : 4 + 65536 * 4 + 4])[0]
    ip_seg_offset = 4 + 65536 * 4 + 4 
    
    for i in range(0, int(ip_segs_len/9)):
        c = ipdb_content[4 + 65536 * 4 + 4 + i * 9: 4 + 65536 * 4 + 4 + (i + 1) * 9]
        c2 = ipdb_content[4 + 65536 * 4 + 4 + (i + 1) * 9 : 4 + 65536 * 4 + 4 + (i + 2) * 9]
        flag = struct.unpack("B", c[8 : 9])[0]
        if (flag == 1): 
            continue
        start = struct.unpack("!L", c[0 : 4])[0]
        if (i == int(ip_segs_len/9) - 1):
            end = 0xffffffff
        else:
            end = struct.unpack("!L", c2[0 : 4])[0] - 1
        content_addr = struct.unpack("!L", c[4: 8])[0]
        content_len = struct.unpack("!L", ipdb_content[ip_seg_offset + content_addr : ip_seg_offset + content_addr + 4])[0]
        ret_val.append( (int2ip(start), int2ip(end), ipdb_content[ip_seg_offset + content_addr + 4 : ip_seg_offset + content_addr + 4 + content_len]) )       
            
    return ret_val
    
    
    
def test():
    data = [("200.200.0.2", "255.255.3.3", "zzzzzz"),
            ("0.0.10.0", "127.0.0.0", "xxxxxxxx"),
            ("200.0.0.1", "200.0.0.1", "aaa"),
            ("127.0.0.1", "192.168.1.0", "yyyyyy"),
            ("192.168.100.1", "192.168.200.0", "xxxxxxxx"),
            
            ]
    
    #create_ipdb(data)   
    
    #print (ipdb_find("ipdb", "200.201.0.2"))
    
    r = ipdb_load("ipdb")
    print (r)

if __name__ == "__main__":
    
    test()