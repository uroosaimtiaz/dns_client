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
        self.nscount = 0
        self.arcount = 0
        self.domain_length = 0

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
        self.nscount = nscount
        self.arcount = arcount
        self.offset = 12  # Skip header


    def parse_and_print_dns_question(self, qtype=1, qclass=1):
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
        while self.response[self.offset] != 0:
            label_length = self.response[self.offset]
            label = self.response[self.offset + 1 : self.offset + 1 + label_length].decode("utf-8")
            domain += label + "."
            self.offset += label_length + 1 # Skip the length byte
        self.domain = domain
        print(f";{domain}                   {qclass_names[qclass]}      {qtype_names[qtype]}\n")
        self.domain_length = self.offset - 12 + 1 # subtract 12 for the header and add 1 to include the null byte
        self.offset += 5  # Skip null byte and QTYPE/QCLASS
    
    def parse_and_print_dns_answer(self):
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
        for _ in range(self.ancount): # Loop through the number of answers, which is 1 by default for our client
            if self.response[self.offset] >= 0xC0:  # The domain name is compressed
                self.offset += 2  # Skip the pointer
            else:  # The domain name is not compressed
                self.offset += self.domain_length # Skip the domain name

            type, class_, ttl, rdlength = struct.unpack('>HHIH', self.response[self.offset:self.offset + 10])
            self.offset += 10
            
            if type == 1:  # A record
                '''
                The RDLLENGTH field specifies the length of the RDATA field, which is 4 bytes for an A record.
                The RDATA field contains the IP address of the domain name.
                '''
                ip_address = socket.inet_ntoa(self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      A       {ip_address}")
                self.offset += rdlength
            elif type == 2:  # NS record
                nameserver, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      NS      {nameserver}")
            elif type == 5:  # CNAME record
                canonical_name, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      CNAME   {canonical_name}")
            elif type == 28:  # AAAA record
                ipv6_address = socket.inet_ntop(socket.AF_INET6, self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      AAAA    {ipv6_address}")
                self.read_name(self.response, self.offset)

    def read_name(self, response, offset):
        '''
        Converts a sequence of labels into a domain name, used for parsing the domain name in the answer sections.
        '''
        labels = [] # Initialize an empty list to store the labels

        while True:
            length = response[offset]

            # Check for a pointer
            if length >= 0xc0:
                pointer = struct.unpack_from('!H', response, offset)[0] # Unpack the pointer
                pointer &= 0x3fff  # Remove the first two bits
                label, _ = self.read_name(response, pointer)  # Ignore the returned offset
                offset += 2  # Skip the pointer
                break
            elif length == 0:
                offset += 1  # Skip the null byte
                break
            else:
                label = response[offset + 1 : offset + 1 + length].decode("utf-8")
                labels.append(label)
                offset += 1 + length  # Skip the length byte and the label

        return ".".join(labels), offset

    def parse_and_print_authority_records(self):
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
        for _ in range(self.nscount): # Loop through the number of answers, which is 1 by default for our client
            if self.response[self.offset] >= 0xC0:  # The domain name is compressed
                self.offset += 2  # Skip the pointer
            else:  # The domain name is not compressed
                self.offset += self.domain_length # Skip the domain name

            type, class_, ttl, rdlength = struct.unpack('>HHIH', self.response[self.offset:self.offset + 10])
            self.offset += 10

            if type == 1:  # A record
                '''
                The RDLLENGTH field specifies the length of the RDATA field, which is 4 bytes for an A record.
                The RDATA field contains the IP address of the domain name.
                '''
                ip_address = socket.inet_ntoa(self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      A       {ip_address}")
                self.offset += rdlength
            elif type == 2:  # NS record
                nameserver, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      NS      {nameserver}")
            elif type == 5:  # CNAME record
                canonical_name, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      CNAME   {canonical_name}")
            elif type == 28:  # AAAA record
                ipv6_address = socket.inet_ntop(socket.AF_INET6, self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      AAAA    {ipv6_address}")
                self.read_name(self.response, self.offset)

    def parse_and_print_additional_records(self):
        """
        Parses the additional records section of a DNS response and prints the values of the fields.
        Based on the output of the dig command, the additional records section should look like this:

            ;; ADDITIONAL SECTION:
            ...
        """
        print("\n;; ADDITIONAL SECTION:")
        for _ in range(self.arcount): # Loop through the number of answers, which is 1 by default for our client
            if self.response[self.offset] >= 0xC0:  # The domain name is compressed
                self.offset += 2  # Skip the pointer
            else:  # The domain name is not compressed
                self.offset += self.domain_length # Skip the domain name

            type, class_, ttl, rdlength = struct.unpack('>HHIH', self.response[self.offset:self.offset + 10])
            self.offset += 10
            
            if type == 1:  # A record
                '''
                The RDLLENGTH field specifies the length of the RDATA field, which is 4 bytes for an A record.
                The RDATA field contains the IP address of the domain name.
                '''
                ip_address = socket.inet_ntoa(self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      A       {ip_address}")
                self.offset += rdlength
            elif type == 2:  # NS record
                nameserver, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      NS      {nameserver}")
            elif type == 5:  # CNAME record
                canonical_name, self.offset = self.read_name(self.response, self.offset)
                print(f"{self.domain}             {ttl}     IN      CNAME   {canonical_name}")
            elif type == 28:  # AAAA record
                ipv6_address = socket.inet_ntop(socket.AF_INET6, self.response[self.offset:self.offset + rdlength])
                print(f"{self.domain}             {ttl}     IN      AAAA    {ipv6_address}")
                self.read_name(self.response, self.offset)

    def parse_and_print_dns_response(self, query_time, server_ip='192.168.2.1'):
        """
        Parses the DNS response and prints the values of the fields.

        Based on the output of the dig command, the response should look like this:

        ;; Query time: 11 msec
        ;; SERVER: 192.168.2.1#53(192.168.2.1)
        ;; WHEN: Fri Feb 23 20:04:52 EST 2024
        ;; MSG SIZE  rcvd: 46
        """
        # print("Full response (hexadecimal):\n", self.response.hex())
        self.parse_and_print_header()
        self.parse_and_print_dns_question()
        self.parse_and_print_dns_answer()
        if self.nscount > 0:
            self.parse_and_print_authority_records()
        if self.arcount > 0:
            self.parse_and_print_additional_records()

        print("\n;; Query time: {:.2f} msec".format(query_time * 1000))
        print(";; SERVER: {}#53({})".format(server_ip, server_ip))
        print(";; WHEN: {}".format(time.strftime("%a %b %d %H:%M:%S %Z %Y")))
        print(";; MSG SIZE rcvd: {}".format(len(self.response)))