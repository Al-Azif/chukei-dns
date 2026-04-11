# TODO

- [ ] Add configurable DoH resolver request method support
    ```json
    "doh_resolvers": [
      {"url": "https://1.1.1.1/dns-query", "type": "POST"},
      {"url": "https://1.1.1.1/dns-query?dns={{BASE64}}", "type": "GET"},
      {"url": "https://1.1.1.1/dns-query?name={{DOMAIN}}&type={{RECORD_TYPE}}", "type": "GET"}
    ]
    ```
- [ ] Improve CMake setup, VS Code tasks, and CI workflows
- [ ] Add EDNS0 Option Codes (OPT)
  - [ ] Standard Codes
    ```
      2 	Update Lease 	      Standard 	[RFC9664]
      3 	NSID 	              Standard 	[RFC5001]
      5 	DAU 	              Standard 	[RFC6975]
      6 	DHU 	              Standard 	[RFC6975]
      7 	N3U 	              Standard 	[RFC6975]
      10 	COOKIE 	            Standard 	[RFC7873]
      11 	edns-tcp-keepalive 	Standard 	[RFC7828]
      12 	Padding 	          Standard 	[RFC7830]
      13 	CHAIN 	            Standard 	[RFC7901]
      15 	Extended DNS Error 	Standard 	[RFC8914]
      18 	Report-Channel 	    Standard 	[RFC9567]
      19 	ZONEVERSION 	      Standard 	[RFC9660]
    ```
  - [ ] Optional Codes
- [ ] DNSSEC
- [ ] Use platform-provided certificates on PS4/PS5 instead of a bundled static cert
  - Target path: `/system/common/cert/CA_LIST.cer`
- [ ] Audit PS4/PS5 DNS behavior and add missing protocol features
- [ ] Review performance: Only micro-optimizations remain after feature and correctness work
- [ ] Consider replacing C++ exceptions with error codes for C interoperability
  - Evaluate tradeoffs before committing to this change
