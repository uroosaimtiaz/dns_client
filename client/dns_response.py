# dns_response.py
import struct
import socket
import time

class DNSResponse:
    def __init__(self, response):
        self.response = response
        self.domain = ""
        self.offset = 0
        self.ancount = 0
        self.authority_records = 0
        self.additional_records = 0

    def parse_and_print_header(self):
        """
        Parses the header of a DNS response and prints the values of the fields. A DNS header is 12 bytes long 
        and is identical in both the query and response messages. Based on the output of the dig command, the 
        header should look like this:
            uroosaimtiaz@Uroosas-MBP cisc335 % dig +noedns facebook.com

            ; <<>> DiG 9.10.6 <<>> +noedns facebook.com
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1010
            ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        """

        (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('>HHHHHH', self.response[:12])

        '''
        Diagram of flags:
        15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            - QR (bit 15): Query/Response flag
            - Opcode (bits 11-14): Operation code
            - AA (bit 10): Authoritative Answer flag
            - TC (bit 9): Truncation flag
            - RD (bit 8): Recursion Desired flag
            - RA (bit 7): Recursion Available flag
            - Z (bits 4-6): Reserved for future use
            - RCODE (bits 0-3): Response code

        The use of a 'mask' and 'shift' operations is a common technique to extract specific bits from a binary
        number.
        '''
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 15
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        z = (flags >> 4) & 7
        rcode = flags & 15

        opcode_names = ["QUERY", "IQUERY", "STATUS", None, "NOTIFY", "UPDATE"]
        rcode_names = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"]

        print(";; ->>HEADER<<- opcode: {}, status: {}, id: {}".format(opcode_names[opcode], rcode_names[rcode], transaction_id))
        print(";; flags: qr rd ra; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}".format(qdcount, ancount, nscount, arcount))
        print("Number of authority records: {}".format(nscount))
        self.ancount = ancount
        self.authority_records = nscount
        self.offset = 12  # Skip header


    def parse_and_print_dns_question(self, offset, qtype=1, qclass=1):
        """
        Parses the question section of a DNS response and prints the domain name.
        Based on the output of the dig command, the question section should look like this:
            uroosaimtiaz@Uroosas-MBP cisc335 % dig +noedns facebook.com
            ...
            ;; QUESTION SECTION:
            ;facebook.com.                  IN      A
        
        The question section contains the following fields:
            - domain name
            - class (IN for Internet)
            - type (A for IPv4 address)
        
        The relevant response section contains the domain name, a null byte, the QTYPE, 
        and the QCLASS. The domain name is a sequence of labels, each prefixed with a byte
        that specifies the length of the label. The domain name is terminated with a null byte.
        """
        print("\n;; QUESTION SECTION:")
        qtype_names = [None, "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA"]
        qclass_names = [None, "IN", "CS", "CH", "HS"]
        domain = ""
        while self.response[offset] != 0:
            label_length = self.response[offset]
            label = self.response[offset + 1 : offset + 1 + label_length].decode("utf-8")
            domain += label + "."
            offset += label_length + 1 # Skip the length byte
        self.domain = domain
        print(f";{domain}                  {qclass_names[qclass]}      {qtype_names[qtype]}\n")
        return offset + 5  # Skip null byte and QTYPE/QCLASS
    
    def parse_and_print_dns_answer(self, offset, ancount=1, qtype=1, qclass=1):
        """
        Parses the answer section of a DNS response and prints the values of the fields.
        Based on the output of the dig command, the answer section should look like this:

            ;; ANSWER SECTION:
            facebook.com.           35      IN      A       157.240.254.35

        with the following fields:
            - domain name
            - time to live (TTL)
            - class (IN for Internet)
            - type (A for IPv4 address)
            - IP address

        The relevant response section contains the domain name (which may be compressed), 
        followed by the TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes), and RDATA fields.

        Variable  2       2        4       2        Variable
        +--------+--------+--------+-------+--------+------+
        |  NAME  |TYPE    |CLASS   |TTL    |RDLEN   |RDATA |
        +--------+--------+--------+-------+--------+------+
        """
        print(";; ANSWER SECTION:")
        qtype_names = [None, "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA"]
        qclass_names = [None, "IN", "CS", "CH", "HS"]
        for _ in range(self.ancount): # Loop through the number of answers, which is 1 by default for our client
            offset += 2 # Skipping compressed domain name pointer
            type, class_, ttl, rdlength = struct.unpack('>HHIH', self.response[offset:offset + 10])
            offset += 10
            if type == 1:  # A record
                '''
                The RDLLENGTH field specifies the length of the RDATA field, which is 4 bytes for an A record.
                The RDATA field contains the IP address of the domain name.
                '''
                ip_address = socket.inet_ntoa(self.response[offset:offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      A       {ip_address}")
            offset += rdlength

    def parse_and_print_authority_records(self, offset, nscount=0):
        """
        Parses the authority section of a DNS response and prints the values of the fields.
        Based on the output of the dig command, the authority section should look like this:

            ;; AUTHORITY SECTION:
            facebook.com.           172800  IN      NS      ns-2048.awsdns-64.com.

        with the following fields:
            - domain name
            - time to live (TTL)
            - class (IN for Internet)
            - type (NS for name server)
            - name server

        The relevant response section contains the domain name (which may be compressed), 
        followed by the TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes), and RDATA fields.

        Variable  2       2        4       2        Variable
        +--------+--------+--------+-------+--------+------+
        |  NAME  |TYPE    |CLASS   |TTL    |RDLEN   |RDATA |
        +--------+--------+--------+-------+--------+------+
        """
        print("\n;; AUTHORITY SECTION:")
        qtype_names = [None, "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA"]
        qclass_names = [None, "IN", "CS", "CH", "HS"]
        for _ in range(nscount): # Loop through the number of authority records
            offset += 2 # Skipping compressed domain name pointer
            type, class_, ttl, rdlength = struct.unpack('>HHIH', self.response[offset:offset + 10])
            offset += 10
            if type == 1:  # A record
                ip_address = socket.inet_ntoa(self.response[offset:offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      A       {ip_address}")
            elif type == 2:  # NS record
                nameserver = self.response[offset:offset + rdlength].decode("utf-8")
                print(f"{self.domain}             {ttl}     IN      NS      {nameserver}")
            elif type == 5:  # CNAME record
                canonical_name = self.response[offset:offset + rdlength].decode("utf-8")
                print(f"{self.domain}             {ttl}     IN      CNAME   {canonical_name}")
            elif type == 15:  # MX record
                preference, = struct.unpack('>H', self.response[offset:offset + 2])
                exchange = self.response[offset + 2:offset + rdlength].decode("utf-8")
                print(f"{self.domain}             {ttl}     IN      MX      {preference} {exchange}")
            elif type == 16:  # TXT record
                txt_data = self.response[offset + 1:offset + rdlength].decode("utf-8")  # Skip the length byte
                print(f"{self.domain}             {ttl}     IN      TXT     {txt_data}")
            elif type == 28:  # AAAA record
                ipv6_address = socket.inet_ntop(socket.AF_INET6, self.response[offset:offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      AAAA    {ipv6_address}")
            offset += rdlength
        return offset


    def parse_and_print_additional_records(self, offset, arcount=0):
        """
        Parses the additional records section of a DNS response and prints the values of the fields.
        Based on the output of the dig command, the additional records section should look like this:

            ;; ADDITIONAL SECTION:
            ...
        """
        print("\n;; ADDITIONAL SECTION:")
        pass

    def parse_and_print_dns_response(self, start_time, server_ip='8.8.8.8'):
        """
        Parses the DNS response and prints the values of the fields.

        Based on the output of the dig command, the response should look like this:

        ;; Query time: 11 msec
        ;; SERVER: 192.168.2.1#53(192.168.2.1)
        ;; WHEN: Fri Feb 23 20:04:52 EST 2024
        ;; MSG SIZE  rcvd: 46
        """
        self.parse_and_print_header()
        self.offset = self.parse_and_print_dns_question(12)
        self.parse_and_print_dns_answer(self.offset)
        if self.authority_records > 0:
            print("\n;; AUTHORITY SECTION: ")
            self.parse_and_print_authority_records(self.offset)
        if self.additional_records > 0:
            self.parse_and_print_additional_records(self.offset)

        query_time = int((time.time() - start_time) * 1000)  # Calculate the query time in milliseconds
        print("\n;; Query time: {} msec".format(query_time))
        print(";; SERVER: {}#53({})".format(server_ip, server_ip))
        print(";; WHEN: {}".format(time.strftime("%a %b %d %H:%M:%S %Z %Y")))
        print(";; MSG SIZE rcvd: {}".format(len(self.response)))