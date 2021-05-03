# CNAME Cloaking repo for Nate Mendes's CSEC-380 Blog

## Configuration

Install `requirements.txt`

Insert pcap file as `my_pcap2.pcap` in main directory, or use default pcap file

Run `main.py` in terminal with no arguments

# Results

| Original Subdomain | DNS resolved Domain   | Cloaking
| --- | --- | --- |
| <DNS_SCHEME>.URL | <DNS_SCHEME>.URL   | Boolean | 


# Example Output


| Original Subdomain | DNS resolved Domain   | Cloaking
| --- | --- | --- |
| `smetrics.redhat.com.` | `redhat.com.ssl.sc.omtrdc.net`   | `True` | 
| `smetrics.redhat.com.` | `redhat.com.ssl.sc.omtrdc.net`   | `True` | 

# Example Video

[![Video exampling script usage](https://img.youtube.com/vi/lym2KEEcZ4I/0.jpg)](https://www.youtube.com/watch?v=lym2KEEcZ4I "Watch how to use this simple script on any website")

# Issues
1) Duplicate CNAME Claoking domains will appear
2) May review TypeError on result, but will not exit program
3) Relies on a *possibly* outdated tracking filter list, last updated on **04/28/2021**
