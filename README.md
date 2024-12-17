### **DNS Server Project**

---

### **1. Project Scope**

The goal of the project is to implement a **DNS server** that is compliant with the fundamental DNS protocol standards as specified in **RFC 1034**, **RFC 1035**, and **RFC 2181**. The system will be designed to handle common DNS queries (e.g., A, CNAME, MX) and provide basic DNS functionalities.

#### **Key Functionalities:**

- **DNS Query Resolution**: The server will accept queries from clients and return corresponding DNS records (e.g., IP addresses for A records, canonical names for CNAME, etc.).
  
- **Multiple Record Types**: The server will support querying and returning several DNS record types:
  
  - A (Address record)
  - CNAME (Canonical Name record)
  - MX (Mail Exchange record)
  - TXT (Text record)
  - NS (Name Server record)
- **Zone Management**: The server will use **standard DNS zone files (master files)** to store and manage DNS records for various domains. These files will serve as the authoritative source of data for the domains the server is responsible for.
  
- **Query Handling**: The server will handle both **recursive and authoritative queries**. For authoritative queries, it will provide direct answers from the zone files. For recursive queries, it will forward requests to upstream DNS servers (if required).
  
- **Error Handling**: The server will return appropriate error messages based on the DNS status codes (RCODE) defined in the RFCs.
  
- **UDP/TCP Communication**: The server will handle DNS requests over **UDP** (for most queries) and **TCP** (for larger responses).
  

---

### **2. Goals**

The goals of the DNS server project are to:

1. **Comply with DNS RFCs**: The server should fully adhere to the **DNS message format** and **protocol behavior** defined in **RFC 1034** (concepts and facilities), **RFC 1035** (implementation and specification), and **RFC 2181** (clarifications to DNS).
  
2. **Implement Robust Query Handling**: The server must handle different query types (A, CNAME, NS, MX, TXT) and provide accurate, RFC-compliant responses.
  
3. **Provide Real-time DNS Responses**: The DNS server should offer quick responses for common domain queries (such as resolving domain names to IP addresses).
  
4. **Handle Large Responses with Truncation**: The server should correctly handle large DNS responses that exceed the 512-byte UDP limit, using TCP for truncation cases.
  
5. **Error Management**: Implement clear and RFC-compliant error codes (e.g., SERVER_FAILURE, etc.) to inform clients of issues when queries cannot be resolved.
  

---

### **3. Functionalities**

The DNS server will have the following functionalities:

#### **a. DNS Query Parsing and Handling**

- **Receive DNS Queries**: The server will listen for incoming DNS requests on port 53 over **UDP** (for most queries) and **TCP** (for large responses).
  
- **Parse DNS Queries**: The server will parse DNS queries to extract the requested domain name, record type, and other relevant information (e.g., class, recursion desired).
  
- **Resolve DNS Queries**:
  
  - For **authoritative** queries, the server will query its **local DNS zone files** to resolve domain names to the appropriate records.
  - For **recursive** queries, the server will query upstream DNS servers.
- **Return DNS Responses**: The server will construct a DNS response with the following sections:
  
  - **Header**: Includes information like transaction ID, flags (e.g., recursion desired), and response code (RCODE).
  - **Question**: Echoes the original query.
  - **Answer**: Contains the resolved resource records (e.g., IP addresses for A records).
  - **Authority**: Provides authoritative name servers for the domain.
  - **Additional**: Contains additional information (e.g., related records).

##

#### **b. Error Handling**

- **RCODE Values**: The server will handle various error scenarios based on the **RCODE** field in the DNS response header:
  
  - **0**: No error (successful query).
  - **1**: Format error (invalid query).
  - **3**: NXDOMAIN (domain not found).
  - **4**: Not implemented (unsupported query type).
  - **5**: Refused (server refused the query, e.g., due to security restrictions).
- **Truncation (TC)**: The server will check if a response exceeds the 512-byte limit for UDP responses. If so, it will set the **TC** (Truncated) flag and advise the client to retry the query over **TCP**.
  

#### **c. Communication Protocols**

- **UDP (User Datagram Protocol)**: The server will handle DNS queries and responses over UDP for standard client-server communication.
  - UDP is preferred for fast, lightweight communication, as most DNS queries fit within the 512-byte limit.
- **TCP (Transmission Control Protocol)**: The server will use TCP for large responses (those greater than 512 bytes) and zone transfers.
  - The server will set the **TC (Truncated)** flag in the DNS response header when a message exceeds 512 bytes over UDP, signaling the client to retry over TCP.

#### **d. Performance and Scalability**

- **Concurrency**: The server should be capable of handling multiple client queries concurrently by using **threading** or **multiprocessing** to ensure efficient query processing.
  

#### **e. Logging and Monitoring**

- The server should maintain logs of all incoming queries, responses, and errors for troubleshooting and monitoring.
  - **Query count**: Total number of queries processed.
  - **Error count**: Number of failed queries and error codes.
  - **Active connections**: List of current active client connections.

---

### **4. System Architecture**

The system architecture is based on a client-server model. The DNS server is the central component that handles client queries, processes them using zone files, and responds with appropriate resource records. The system is designed to:

1. Process DNS queries over UDP and TCP.
2. Support various record types (A, CNAME, NS, MX, SOA, TXT).
3. Allow zone management through standard zone files (master files).

#### **Architecture Diagram**

```
+--------------------+
| DNS Client         |
| - Web browsers     |
| - OS resolvers     |
| - nslookup         |
+--------------------+
           |
           | DNS Query (UDP/TCP)
           v
+--------------------+      +--------------------+
| DNS Server         | <--> | DNS Zone Files     |
| - Query Processor  |      | - Master Files     |
| - Response Builder |      +--------------------+
+--------------------+      
           |
           | DNS Response (UDP/TCP)
           v
+--------------------+
| DNS Client         |
+--------------------+
```

---

### **5. Components and Their Interactions**

#### **1. DNS Server**

The server is responsible for:

- Listening for incoming DNS queries on UDP/TCP port 53.
- Parsing DNS queries based on the message format defined in RFC 1035.
- Interacting with the zone files to retrieve resource records.
- Building and sending DNS responses to clients.
- Logging server activities such as active connections, query statistics, and errors.

**Subcomponents**:

1. **Query Processor**: Parses incoming queries, validates them, and extracts the domain name and record type.
2. **Response Builder**: Constructs DNS responses, including headers, questions, answers, authority, and additional sections.
3. **Transport Layer**:
  - **UDP**: Handles queries and responses that fit within 512 bytes.
  - **TCP**: Handles queries requiring zone transfers or responses exceeding 512 bytes.

#### **2. DNS Client**

The client initiates DNS queries to resolve domain names into IP addresses or retrieve other resource records. Typical clients include:

- Web browsers (e.g., Chrome, Firefox).
- OS DNS resolvers (e.g., Windows, Linux).

**Interaction**:

1. The client sends a DNS query to the server over UDP or TCP.
2. The client receives a response and processes the result.

#### **3. DNS Zone Files**

The **zone files** are the key component for storing DNS resource records (A, CNAME, MX, etc.) for the domains the server is responsible for. These files are plain text files with a defined structure.

- **Master Zone Files** will store the authoritative records for each domain.
- The server will read the zone files on startup and use the data to respond to queries.

####

---

### **6. Communication Protocols/Message Protocols**

#### **1. Transport Protocols**

- **UDP**:
  - Used for most DNS queries and responses.
  - Limited to 512-byte messages.
  - Lightweight and fast but unreliable (packet loss).
- **TCP**:
  - Used for responses exceeding 512 bytes.
  - Reliable but slower than UDP.
- **Port**:
  - Both UDP and TCP use port 53.

#### **2. DNS Message Format**

DNS messages consist of the following sections (RFC 1035, Section 4.1).

##### **Header Section**

| Field | Size (bits) | Description |
| --- | --- | --- |
| ID  | 16  | Unique identifier for matching queries and responses. |
| QR  | 1   | Query (0) or Response (1). |
| Opcode | 4   | Type of query (Standard = 0, Inverse = 1, Status = 2). |
| AA  | 1   | Authoritative Answer (set by authoritative servers). |
| TC  | 1   | Truncation (set if message is truncated). |
| RD  | 1   | Recursion Desired (client requests recursive resolution). |
| RA  | 1   | Recursion Available (server supports recursion). |
| Z   | 3   | Reserved (must be 0). |
| RCODE | 4   | Response code (e.g., 0 = No Error, 3 = NXDOMAIN). |
| QDCOUNT | 16  | Number of entries in the Question section. |
| ANCOUNT | 16  | Number of entries in the Answer section. |
| NSCOUNT | 16  | Number of entries in the Authority section. |
| ARCOUNT | 16  | Number of entries in the Additional section. |

##### **Question Section**

| Field | Description |
| --- | --- |
| QNAME | Domain name being queried, encoded as labels. |
| QTYPE | Record type (A = 1, CNAME = 5). |
| QCLASS | Class (IN = 1 for Internet). |

##### **Answer, Authority, and Additional Sections**

| Field | Description |
| --- | --- |
| NAME | Domain name or pointer to the domain name in the message. |
| TYPE | Record type |
| CLASS | Class |
| TTL | Time-to-live value in seconds. |
| RDLENGTH | Length of the resource data. |
| RDATA | Resource data (e.g., IP address for A records, domain name for CNAME records). |

---

### **Handling Specific Protocol Features And Optimizatoin (for phase 3 and 4)**

#### **1. Compression**

- Domain names are compressed using pointers to earlier occurrences in the message. This reduces redundancy in larger responses (RFC 1035: Section 4.1.4).

#### **2. Truncation**

- If the server's response exceeds 512 bytes over UDP, it sets the `TC` flag. The client then retries over TCP to retrieve the full response (RFC 1035: Section 4.2.1).

#### **3. Error Codes (RCODE)**

- **0**: No error.
- **1**: Format error (invalid query).
- **2**: Server failure (unable to process query).
- **3**: Name error (NXDOMAIN, non-existent domain).
- **4**: Not implemented (unsupported query type).
- **5**: Refused (policy or security reasons).

---
