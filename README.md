# DNS Server
### Task: Write a miniature DNS server that will serve AAAA queries.
The Domain Name System (DNS) provides, among other things, the mapping between human-meaningful hostnames like lms.unimelb.edu.au and the numeric IP addresses that indicate where packets should be sent. DNS consists of a hierarchy of servers, each knowing a portion of the complete mapping.

In this practice, a DNS server will be implemented that accepts requests for IPv6 addresses and serves them either from its own cache or by querying servers higher up the hierarchy. Each transaction consists of at most four messages: one from your client to you, one from you to your upstream server, one from your upstream server to you and one from you to your client. The middle two can be sometimes skipped if you cache some of the answers.
The format for DNS request and response messages are described in [1].
In a DNS system, the entry mapping a name to an IPv6 address is called a AAAA (or “quad A”) record
[2]. Its “record type” is 28 (QType in [2]).
The server will also keep a log of its activities. This is important for reasons such as detecting denial-of-
service attacks, as well as allowing service upgrades to reflect usage patterns.
For the log, you will need to print a text version of the IPv6 addresses. IPv6 addresses are 128 bits long. They are represented in text as eight colon-separated strings of 16-bit numbers expressed in hexadecimal. As a shorthand, a string of consecutive 16-bit numbers that are all zero may be replaced by a single “::”. Details are in [3].
