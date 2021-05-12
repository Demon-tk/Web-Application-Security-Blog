# CNAME Cloaking repo for Nate Mendes's CSEC-380 Blog

## What it does

Used to detect CNAME Cloaking on recorded browsing sessions

*Methodology:*

1) Read recorded pcap file
2) Parse the pcap files for DNS requests that may show possible CNAME cloaking
3) Download and [parse](https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters) (regex style) an
   update [AgGuard filterlist](https://github.com/AdguardTeam/AdguardFilters/blob/master/SpywareFilter/sections/tracking_servers.txt)
4) Filter out tracking domains that are not hiding
5) Locate domain(s) that use CNAME Cloaking
6) Pretty print the results

## Configuration

Install `requirements.txt`

Insert pcap file as `my_pcap2.pcap` in the main directory, or use default pcap file

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

[![Video exampling script usage](https://www.lifewire.com/thmb/xu0jkFPan7bOG0VKxkgU8xr8Xu4=/2644x1133/filters:no_upscale():max_bytes(150000):strip_icc()/GettyImages-585297068-52005387a57248a19e3ee29bc1af44b4.jpg)](https://www.youtube.com/watch?v=lym2KEEcZ4I "Watch how to use this simple script on any website")

# Issues

1) Duplicate CNAME Claoking domains will appear


##License
Code is not authoirized for use by any third-parties unless explicit permission is given by the author.  

