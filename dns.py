import socket
import glob
import json

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zone():
	jsonzone = {}
	zonefiles = glob.glob('*.zone')
	
	for zone in zonefiles:
		with open(zone) as zonedata:
			data = json.load(zonedata)
			zonename = data["$origin"]
			jsonzone[zonename] = data
	#print(jsonzone)
	return jsonzone

zonedata = load_zone()

def getflags(flags):
	
	byte1 = bytes(flags[:1]) #The first bit of flags (QR, OPCODE, AA, TC, RD)
	byte2 = bytes(flags[1:2]) #The second bit of flags (RA, Z, RCODE)
	
	rflags = ''
	
	QR = '1'
	OPCODE = ''
	for bit in range(1,5):
		OPCODE += str(ord(byte1)&(1<<bit)) #taking the bits one by one
	AA = '1'
	TC = '0'
	RD = '0'
	
	RA = '0'
	Z = '000'
	RCODE = '0000'
	return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder = 'big') + int(RA+Z+RCODE, 2).to_bytes(1, byteorder = 'big')



def getquestiondomain(data):
	state = 0
	expectedlength = 0
	domainstring = ''
	domainparts = []
	x = 0
	y = 0
	for byte in data:
		if state == 1:
			if byte != 0:
				domainstring += chr(byte)
			x += 1
			if x == expectedlength:
				domainparts.append(domainstring)
				domainstring = ''
				state = 0
				x = 0
			if byte == 0:
				#domainparts.append(domainstring)
				break
			
		else:
			state = 1
			expectedlength = byte
		y += 1
	
	questiontype = data[y: y+2]
	#print(questiontype)
	return(domainparts, questiontype)

def getzone(domain):
	global zonedata
	zone_name = ".".join(domain) +"."
	return zonedata[zone_name]

def getrecs(data):
	domain, questiontype = getquestiondomain(data)
	
	qt =''
	
	if questiontype == b'\x00\x01':
		qt = 'a'   #A-records are used as IP address lookups
	
	zone = getzone(domain)
	
	return(zone[qt], qt, domain)
	
def buildquestion(domainname, rectype):
	qbytes = b''
	
	for part in domainname:
		length = len(part)
		qbytes += bytes([length])
		# we should add length of the name as the first byte
		
		for char in part:
			qbytes += ord(char).to_bytes(1, byteorder = 'big')
			#The characters are added
	#End of domain name byte
	qbytes += (0).to_bytes(1, byteorder = 'big')
	#Record type byte
	if rectype == 'a':
		qbytes += (1).to_bytes(2, byteorder ='big')
	#Class byte
	qbytes += (1).to_bytes(2, byteorder ='big')
	return qbytes
	
def rectobytes(domainname, rectype, recttl, recval):
	
	rbytes = b'\xc0\x0c' #compression of name (offset value)
	
	if rectype == 'a':
		rbytes = rbytes + bytes([0]) + bytes([1])
		
	rbytes = rbytes + bytes([0]) + bytes([1])
	
	rbytes += int(recttl).to_bytes(4, byteorder = 'big')
	
	if rectype == 'a':
		rbytes = rbytes + bytes([0]) + bytes([4])
		
		for part in recval.split('.'):
			rbytes += bytes([int(part)])
	return rbytes
	

def buildresponse(data):
	#Transaction ID
	TransactionID = data[0:2] #getting the transaction ID
	ID = ''
	
	for byte in TransactionID:
		ID += hex(byte)[2:]

	Flags = getflags(data[2:4]) 
	
	#Question Count
	QDCOUNT = b'\x00\x01'
	
	#Answer Count  -- depends on the domain
	ANCOUNT = (len(getrecs(data[12:])[0])).to_bytes(2, byteorder = 'big')
	#print(ANCOUNT)
	
	#nameserver count
	NSCOUNT = (0).to_bytes(2, byteorder= 'big')
	
	#additional count
	ARCOUNT = (0).to_bytes(2, byteorder= 'big')
	
	dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
	dnsbody = b''
	
	records, rectype, domainname = getrecs(data[12:])
	
	dnsquestion = buildquestion(domainname, rectype)
	
	for record in records:
		dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])
	return dnsheader + dnsquestion + dnsbody


while 1:
	data, addr = sock.recvfrom(512)
	r = buildresponse(data)
	sock.sendto(r, addr)
