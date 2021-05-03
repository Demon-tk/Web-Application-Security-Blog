# CNAME Cloaking repo for Nate Mendes's CSEC-380 Blog

## Configuration

Insert pcap file as `my_pcap2.pcap` in main directory, or use default pcap file:

# Results

| Original Subdomain | DNS resolved Domain   | Cloaking
| --- | --- | --- |
| <DNS_SCHEME>.URL | <DNS_SCHEME>.URL   | Boolean | 


# Example Output


| Original Subdomain | DNS resolved Domain   | Cloaking
| --- | --- | --- |
| `smetrics.redhat.com.` | `redhat.com.ssl.sc.omtrdc.net`   | `True` | 
| `smetrics.redhat.com.` | `redhat.com.ssl.sc.omtrdc.net`   | `True` | 


# Bugs
1) Duplicate CNAME Claoking domains will appear
2) May review TypeError on result, but will not exit program
