# dns_query.py
import secrets
import struct

class DNSQuery:
    def __init__(self, domain):
        self.domain = domain
        
    def generate_transaction_id(self):
        """
        Generates a random integer transaction ID for a DNS query. A 2-byte (or 16-bit) number can represent values from 0 to 2^16 - 1, 
        which is 65535.
        """
        return secrets.randbelow(65536)

    def create_dns_query_header(self, id=None, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
        """
        Generates a DNS query header with default parameters for a standard A-record query for a single domain.
        The header is a 12-byte (or 96-bit) section of the DNS query message. It contains the following fields in order:

        | Field | Description                                                                   | Size (bits) | Default Value (in queries) |
        |-------|-------------------------------------------------------------------------------|-------------|----------------------------|
        | ID    | Unique identifier to match queries with responses.                            | 16          | Random 16-bit number       |
        | QR    | Specifies whether this message is a query or a response.                      | 1           | 0 (query)                  |
        | OPCODE| Specifies the type of the query.                                              | 4           | 0 (standard query)         |
        | AA    | Indicates if the responding DNS server is an authority for the domain queried.| 1           | 0 (not authoritative)      |
        | TC    | Indicates if the message was truncated.                                       | 1           | 0 (not truncated)          |
        | RD    | Expresses the client's desire for the query to be pursued recursively.        | 1           | 1 (recursion desired)      |
        | RA    | Indicates if the DNS server can perform recursive queries.                    | 1           | 0 (recursion not available)|
        | Z     | Reserved for future use.                                                      | 3           | 0 (reserved)               |
        | RCODE | Used as a response code.                                                      | 4           | 0 (no error)               |
        | QDCOUNT| Specifies the number of questions in the message.                            | 16          | 1 (one question)           |
        | ANCOUNT| Specifies the number of answers in the message.                              | 16          | 0 (no answers)             |
        | NSCOUNT| Specifies the number of authority records in the message.                    | 16          | 0 (no authority records)   |
        | ARCOUNT| Specifies the number of additional records in the message.                   | 16          | 0 (no additional records)  |
        """    
        id = self.generate_transaction_id()  # get a random 16-bit number

        '''
        The struct.pack function can be used to format the header data into a binary string according to the RFC 1035 specification.
        The format string '>HBBHHHH' specifies the layout of the data:
            - '>' means the data is in big-endian
            - 'H' stands for a 16-bit unsigned integer (for the ID field).
            - 'B' stands for an 8-bit unsigned integer (for the QR, OPCODE, AA, TC, and RD fields).
            - 'B' stands for another 8-bit unsigned integer (for the RA, Z, and RCODE fields).
            - 'HHHH' stands for four 16-bit unsigned integers (for the QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT fields).
        '''
        
        header = struct.pack(
            '>HBBHHHH', 
            id,
            # First 8-bit unsigned integer field:
            ((qr << 7) |  # QR value (1 bit) shifted 7 bits to the left
            (opcode << 3) |  # OPCODE value (4 bits) shifted 3 bits to the left
            (aa << 2) |  # AA value (1 bit) shifted 2 bits to the left
            (tc << 1) |  # TC value (1 bit) shifted 1 bit to the left
            rd),  # RD value (1 bit)

            # Second 8-bit unsigned integer field:
            ((ra << 7) |  # RA value (1 bit) shifted 7 bits to the left
            (z << 4) |  # Z value (3 bits) shifted 4 bits to the left
            rcode),  # RCODE value (4 bits)

            qdcount,  # QDCOUNT field (16 bits)
            ancount,  # ANCOUNT field (16 bits)
            nscount,  # NSCOUNT field (16 bits)
            arcount  # ARCOUNT field (16 bits)
        )

        # The result is a 96 bit string that represents the DNS query header.
        return header
    
    def create_dns_query_question(self, qtype=1, qclass=1):
        """
        Generates a DNS query question section for a standard A-record query for a single domain.
        The question section is variable in size and contains the following fields in order:

        | Field   | Description                                                                  | Size (bits) | Default Value (in queries) |
        |---------|------------------------------------------------------------------------------|-------------|----------------------------|
        | QNAME   | The domain name split into labels, each prefixed with number of chars/bytes  | Variable    | N/A                        |
        | QTYPE   | Specifies the type of the DNS query (e.g., A, AAAA, MX, etc.).               | 16          | 1 (A record query)         |
        | QCLASS  | Specifies the class of the query (usually Internet).                         | 16          | 1 (IN - Internet)          |
        
        The domain name is split into its individual parts, with each part prefixed with a byte that specifies the length of the part. 
        Each individual 'label' in the domain name cannot exceed 63 characters, and the total length including the TLD cannot exceed 253 
        characters. Each character is encoded as a single byte using the UTF-8 encoding, and the domain name is terminated with a null byte.
        The question is constructed by concatenating the QNAME, QTYPE, and QCLASS fields.

        The struct module was not used here because the question section is variable in size, and the struct module is used for fixed-size data.
        Instead, the question section is constructed converting the fields to bytes in big-endian format and concatenating them together.
        """
        name = b'' # Initialize an empty byte string
        for part in self.domain.split('.'):
            name += bytes([len(part)]) + part.encode('utf-8') # Length byte followed by the 'label' in bytes
        qtype = (qtype).to_bytes(2, byteorder='big')  # Convert qtype to bytes
        qclass = (qclass).to_bytes(2, byteorder='big')  # Convert qclass to bytes
        return name + b'\x00' + qtype + qclass
    
    def create_dns_query(self):
        """
        RFC 1035 section 4.1.1 and 4.1.2 specify the format of a standard DNS message. The query contains a Header and Question section. 
        The Header section is 12 bytes and contructed using the create_dns_query_header function. The Question section is variable length
        and constructed using the create_dns_query_question function. The two sections are then concatenated to form the complete DNS query message.
        """
        header = self.create_dns_query_header()
        question = self.create_dns_query_question()
        return header + question