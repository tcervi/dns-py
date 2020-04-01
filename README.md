# dns-py
Simple DNS implementation exercise in Python 

The objective on this project is to provide a DNS server in which an user will be able to register domain records and retrieve domain information using standard DNS tools (e.g. dig). 
Registered domain records will be persisted using Python serialization module pickle.

## Domain records registration

The registration interface could be implemented with different approaches: api, cli, gui, udp/tcp messages, etc...
For this first implementation a simple cli was choosed to provide an user interface in which new domain records can be typed as follow:

```
You can register new domains typing it in a single line 
separating fields with whitespaces:  domain_name domain_class domain_type address/info
Example: www.demo-test.com IN A 1.2.3.4
>>>> Enter domain: 
```

Whenever an user types a new domain record this entry will be validated, a message will be displayed with success or error messages and after few seconds the screen will be cleaned and return to initial state waiting for new registration:

```
>>>> Enter domain: www.test123.net IN A 124.231.45.67
Registered domain: [www.test123.net IN A 124.231.45.67]
[2020-04-01 00:51:22] - You entered new domain: [www.test123.net IN A 124.231.45.67]
```

```
>>>> Enter domain: 123test.net IN A 0.0.0.0.1
FAILED to validate: [123test.net IN A 0.0.0.0.1]
[2020-04-01 00:51:59] - You entered an invalid domain: [123test.net IN A 0.0.0.0.1]
```

## Domain information retrieval

To retrieve a registered domain information, one can use stadard tools (e.g. dig) and point it to this server attached ip and port. The server was developed to be able to hander DNS headers, questions and answers as a DNS server should. Examples follow:

```
 dig www.google.com @localhost -p2053

; <<>> DiG 9.11.3-1ubuntu1.11-Ubuntu <<>> www.google.com @localhost -p2053
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8728
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.			IN	A

;; ANSWER SECTION:
www.google.com.		3600	IN	A	1.2.3.4

;; Query time: 4 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Tue Mar 31 21:44:51 -03 2020
;; MSG SIZE  rcvd: 48
```

###### TODO: For now this server is only handling UDP Datagrams, a further improvement would be to finish TCP support to be able to handle a wider range of tools.

###### TODO: When asking for an A record, for example, if the domain is a CNAME entryt a normal DNS Server would handle the hierarchy of answers until it finds an A record to send back. Further improvement is needed to handle this kind of DNS question

## Tests

Unit tests for this project should be placed at ./test/ folder and must added any time a new feature / function is supposed to be developed.
