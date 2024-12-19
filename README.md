### **DNS Server Project**

---

### **1. Project Scope**

The goal of the project is to implement a **DNS server** that is compliant with the fundamental DNS protocol standards as specified in **RFC 1034**, **RFC 1035**, and **RFC 2181**. The system will be designed to handle common DNS queries (e.g., A, CNAME, MX) and provide basic DNS functionalities.

#### **Key Functionalities:**

-   **Basic DNS Query Resolution**: Handling A, CNAME, and MX queries.
-   **UDP Communication**: Implementing DNS requests and responses over UDP.
-   **Basic Error Handling**: Returning essential RCODEs (e.g., No Error, NXDOMAIN).
  

---

### **2. Goals**

The goals of the DNS server project are to:

  
1. **Implement Robust Query Handling**: The server must handle different query types (A, CNAME, NS, MX, TXT) and provide accurate, RFC-compliant responses.
  
2. **Handle Large Responses with Truncation**: The server should correctly handle large DNS responses that exceed the 512-byte UDP limit, using TCP for truncation cases.
  
3. **Error Management**: Implement clear and RFC-compliant error codes (e.g., SERVER_FAILURE, etc.) to inform clients of issues when queries cannot be resolved.
  

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

- **Concurrency**:  The server should be capable of handling multiple client queries concurrently by using threading.
  

#### **e. Logging and Monitoring**

-  The server should maintain logs of incoming queries, responses, and errors.

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
-   Uses a basic lookup mechanism for authoritative queries.
-   Builds and sends DNS responses to clients.
-   Logs server activities.

**Subcomponents**:

1. **Query Processor**: Parses incoming queries and extracts the domain name and record type.
2. **Response Builder**: Constructs basic DNS responses, including headers, questions, and answers.
3. **Transport Layer**:
  - **UDP**: Handles queries and responses that fit within 512 bytes.
  - **TCP**: Handles queries requiring zone transfers or responses exceeding 512 bytes.




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
