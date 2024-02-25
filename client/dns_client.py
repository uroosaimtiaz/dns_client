import socket
import sys
import time
from dns_query import DNSQuery  # Import the DNSQuery class
from dns_response import DNSResponse  # Import the DNSResponse class

def send_dns_query(query, server='8.8.8.8', port=53):
    """
    Sends a DNS query to the specified server (google public DNS by default) using the specified port 
    (53 by default) on the UDP protocol, and returns the response.
    """
    print(f"Sending DNS query to {server} on port {port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (server, port))
        response, _ = sock.recvfrom(4096)
    return response

def main():
    # Check if a hostname was provided
    if len(sys.argv) < 2:
        print("Usage: python3 dns_query.py <hostname>")
        sys.exit(1)

    # Create a DNS query for the provided hostname
    domain = sys.argv[1]
    dns_query = DNSQuery(domain)  # Create a DNSQuery object
    query = dns_query.create_dns_query()  # Use the DNSQuery object to create the query

    # Define the server IP
    server_ip = socket.gethostbyname(socket.gethostname())

    # Record the start time of the query
    start_time = time.time()

    # Send the query and receive the response
    response = send_dns_query(query)

    # Parse and print the DNS response
    dns_response = DNSResponse(response)  # Create a DNSResponse object
    dns_response.parse_and_print_dns_response(start_time)  # Use the DNSResponse object to parse and print the response

if __name__ == "__main__":
    main()