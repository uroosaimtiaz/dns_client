import socket
import sys
import time
from dns_query import DNSQuery  # Import the DNSQuery class
from dns_response import DNSResponse  # Import the DNSResponse class

def send_dns_query(query, server='8.8.8.8', port=53, timeout=5, retries=3):
    """
    Sends a DNS query to the specified server (google public DNS by default) using the specified port 
    (53 by default) on the UDP protocol, and returns the response.
    Simulates the dig command by sending the query 3 times and waiting for a response, then exiting.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _ in range(retries):
            start_time = time.time()
            sock.sendto(query, (server, port))
            try:
                response, _ = sock.recvfrom(4096)
                end_time = time.time()
                query_time = end_time - start_time
                return response, query_time
            except socket.timeout:
                print(f";; communications error to {server}#{port}: timed out")
        print(";; no servers could be reached")
        sys.exit(1)

def main():
    # Check if a hostname was provided
    if len(sys.argv) < 2:
        print("Usage: python3 dns_query.py <hostname>")
        sys.exit(1)

    ''' test cases collected for domain compression or not, for facebook.com
        response = bytes.fromhex('b367818000010001000000000866616365626f6f6b03636f6d00000100010866616365626f6f6b03636f6d00000100010000000f00041f0d5024')
        705f818000010001000000000866616365626f6f6b03636f6d0000010001c00c000100010000003c00041f0d5024
    '''
    # Create a DNS query for the provided hostname
    domain = sys.argv[1]
    
    dns_query = DNSQuery(domain)  # Create a DNSQuery object
    query = dns_query.create_dns_query()  # Use the DNSQuery object to create the query

    # Send the query and receive the response
    response, query_time = send_dns_query(query)

    # Parse and print the DNS response
    dns_response = DNSResponse(response)  # Create a DNSResponse object
    dns_response.parse_and_print_dns_response(query_time)  # Use the DNSResponse object to parse and print the response

if __name__ == "__main__":
    main()