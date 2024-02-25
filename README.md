# DNS Client

This is a simple DNS client implemented in Python. It can send DNS queries to a DNS server and parse the responses.

## Features

- Supports A and MX record queries
- Parses the DNS message header and question, answer, authority, and additional sections
- Handles domain name encoding and decoding

## Usage

To use this DNS client, you need to have Python installed on your machine.

1. Clone this repository:

git clone https://github.com/uroosaimtiaz/dns-client.git

2. Navigate to the repository directory:

cd dns-client/client

3. Run the DNS client with the domain you want to query as an argument:

python dns_client.py google.com

This will send an A record query for 'google.com' to Google's DNS server (8.8.8.8) and print the response.

## Limitations
This DNS client is a simple implementation and does not support all features of the DNS protocol. For example, it does not support recursive queries, caching, or DNSSEC.
