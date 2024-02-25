import socket
import sys
import secrets
import struct
import time

def parse_and_print_dns_response(response, domain, server_ip, start_time):
    (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('>HHHHHH', response[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 15
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    z = (flags >> 4) & 7
    rcode = flags & 15

    opcode_names = ["QUERY", "IQUERY", "STATUS"]
    rcode_names = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"]

    print(";; ->>HEADER<<- opcode: {}, status: {}, id: {}".format(opcode_names[opcode], rcode_names[rcode], transaction_id))
    print(";; flags: qr rd ra; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}".format(qr, qdcount, ancount, nscount, arcount))

    # Question Section
    print("\n;; QUESTION SECTION:")
    print(f";{domain}.                  IN      A\n")

    # Answer Section
    print(";; ANSWER SECTION:")
    offset = 12  # Skip header
    for _ in range(qdcount):  # Skip question section
        while response[offset] != 0:
            offset += 1
        offset += 5  # Skip null byte and QTYPE/QCLASS

    for _ in range(ancount):
        # Skipping the compressed domain name (assuming it's a pointer)
        offset += 2
        type, class_, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
        offset += 10
        if type == 1:  # A record
            ip_address = socket.inet_ntoa(response[offset:offset + rdlength])
            print(f"{domain}.             {ttl}     IN      A       {ip_address}")
        offset += rdlength

    query_time = int((time.time() - start_time) * 1000)  # Calculate the query time in milliseconds
    print("\n;; Query time: {} msec".format(query_time))
    print(";; SERVER: {}#53({})".format(server_ip, server_ip))
    print(";; WHEN: {}".format(time.strftime("%a %b %d %H:%M:%S %Z %Y")))
    print(";; MSG SIZE rcvd: {}".format(len(response)))

# This function is meant to be used after receiving a DNS response for an A query.
# For example:
# domain = "example.com"
# response = send_dns_query(create_dns_query(domain))
# parse_and_print_dns_response(response, domain)
def generate_transaction_id():
    """
    Generates a random transaction ID in the form of a 2-byte string.
    The range of possible transaction IDs is 0 to 65535, inclusive. 
    A 2-byte (or 16-bit) number can represent values from 0 to 
    2^16 - 1, which is 65535. The byteorder parameter is set to 'big'
    to ensure that the most significant byte is first (leftmost), which
    is the standard for DNS specified in the IETF RFC 1035. This is also
    known as big-endian byte order.
    """
    return secrets.randbelow(65536)

def create_dns_query_header(id=None, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
    """
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
    if id is None:
        id = generate_transaction_id()  # Assuming this function generates a random 16-bit number

    # The struct.pack function is used to convert Python values into a binary string according to a format string.
    # The format string '>HBBHHHH' specifies the layout of the data:
    #   '>' means the data is in big-endian order (most significant byte first).
    #   'H' stands for a 16-bit unsigned integer (for the ID field).
    #   'B' stands for an 8-bit unsigned integer (for the QR, OPCODE, AA, TC, and RD fields).
    #   'B' stands for another 8-bit unsigned integer (for the RA, Z, and RCODE fields).
    #   'HHHH' stands for four 16-bit unsigned integers (for the QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT fields).
    header = struct.pack(
        '>HBBHHHH',  # Format string
        id,  # ID field
        # First 8-bit field:
        ((qr << 7) |  # QR value shifted 7 bits to the left
        (opcode << 3) |  # OPCODE value shifted 3 bits to the left
        (aa << 2) |  # AA value shifted 2 bits to the left
        (tc << 1) |  # TC value shifted 1 bit to the left
        rd),  # RD value

        # Second 8-bit field:
        ((ra << 7) |  # RA value shifted 7 bits to the left
        (z << 4) |  # Z value shifted 4 bits to the left
        rcode),  # RCODE value

        qdcount,  # QDCOUNT field
        ancount,  # ANCOUNT field
        nscount,  # NSCOUNT field
        arcount  # ARCOUNT field
    )

    # The result is a binary string that represents the DNS query header.
    return header

def create_dns_query_question(domain, qtype=1, qclass=1):
    """
    | Field   | Description                                                                  | Size (bits) | Default Value (in queries) |
    |---------|------------------------------------------------------------------------------|-------------|----------------------------|
    | QNAME   | The domain name split into labels, each prefixed with number of chars/bytes  | Variable    | N/A                        |
    | QTYPE   | Specifies the type of the DNS query (e.g., A, AAAA, MX, etc.).               | 16          | 1 (A record query)         |
    | QCLASS  | Specifies the class of the query (usually Internet).                         | 16          | 1 (IN - Internet)          |
    
    The domain name is split into its individual parts, and each part is prefixed with a byte that specifies the length of the part. 
    Each individual label in the domain name cannot exceed 63 characters, and the total length including the TLD cannot exceed 253 characters.
    The domain name is terminated with a null byte. The question is then constructed by concatenating all the fields together.
    """
    name = b''
    for part in domain.split('.'):
        name += bytes([len(part)]) + part.encode('utf-8') # Length byte followed by the part in bytes
    qtype = (qtype).to_bytes(2, byteorder='big')  # Convert qtype to bytes
    qclass = (qclass).to_bytes(2, byteorder='big')  # Convert qclass to bytes
    return name + b'\x00' + qtype + qclass

def create_dns_query(domain):
    """
    RFC 1035 section 4.1.1 and 4.1.2 specify the format of a standard DNS message.
    The query contains a Header and Question section. The Header section is 12 bytes and
    contructed using the create_dns_query_header function. The Question section is variable length
    and constructed using the create_dns_query_question function. The two sections are then concatenated
    to form the complete DNS query message.
    """
    header = create_dns_query_header()
    question = create_dns_query_question(domain)
    return header + question


def send_dns_query(query, server='8.8.8.8', port=53):
    """
    Sends a DNS query to the specified server and returns the response.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (server, port))
        response, _ = sock.recvfrom(512)
    return response

def main():
    # Check if a hostname was provided
    if len(sys.argv) < 2:
        print("Usage: python3 dns_query.py <hostname>")
        sys.exit(1)

    # Create a DNS query for the provided hostname
    domain = sys.argv[1]
    query = create_dns_query(domain)

    # Define the server IP
    server_ip = "192.168.2.1"  # Replace with the actual server IP

    # Record the start time of the query
    start_time = time.time()

    # Send the query and receive the response
    response = send_dns_query(query, server_ip)

    # Parse and print the DNS response
    parse_and_print_dns_response(response, domain, server_ip, start_time)

if __name__ == "__main__":
    main()