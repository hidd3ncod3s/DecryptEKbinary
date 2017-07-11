# DecryptEKbinary
Decrypt the initial droppers of various exploit kits

The default behaviour of various exploit kits is, it will download an encrypted/encoded binary after the initial successful exploitation.
The basic architecture of EK maintainance allow us to create an decryptor for many of the EK. The encryption/encoding logic used by any 
one exploit kit is same for some duration. This is a tool i used to decrypt those encrypted/encoded binaries for analysis purpose. Many 
researchers used in-memory dumping for extracting these binaries but many a times i have seen the cases where the hashes are random 
after the dumping. 

I haven't updated this for sometime now. It will definitely work with old pcaps from malware-traffic. It does not consume the pcap file 
as input. You need to extract that particular encrypted/encoded binary file and give that as input to this tool.
