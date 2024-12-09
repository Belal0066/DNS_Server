# DNS_Server

##  Project Planning and Design

### **System Architecture**

The system architecture is based on a client-server model. The DNS server is the central component that handles client queries, processes them using an integrated database, and responds with appropriate resource records. The system is designed to:

1. Process DNS queries over UDP and TCP.
2. Support various record types (A, CNAME, NS, MX, SOA, TXT).
3. Allow zone management through a database backend.

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
| DNS Server         | <--> | DNS Database       |
| - Query Processor  |      | - Zone Files       |
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

### **Components and Their Interactions**

#### **1. DNS Server**

The server is responsible for:

- Listening for incoming DNS queries on UDP/TCP port 53.
- Parsing DNS queries based on the message format defined in RFC 1035.
- Interacting with the database to retrieve resource records.
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

#### **3. DNS Database**

The database stores all DNS zone information, including resource records (A, CNAME, NS, etc.). It provides an interface for the DNS server to:

- Retrieve records based on domain name and record type.
- Update records for dynamic DNS (Phase 3 or 4 feature).
- Maintain zone data for authoritative responses.

**Database Schema**:

- **Domain**: The queried domain name.
- **Record Type**: The type of DNS record (A, CNAME, etc.).
- **Value**: The record's value (e.g., IP address, canonical name).
- **TTL**: Time-to-live value for cache expiration.

####

---

### **Communication Protocols/Message Protocols**

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
