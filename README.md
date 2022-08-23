# 2022-LPE-UAF
Security researchers discovered 3 vulnerabilities in the Linux kernel that could allow a local attacker to elevate privileges and potentially execute malicious code. The proof-of-concept code is publicly available increasing the likelihood of exploitation in the wild. 

### Paper on Dirtycred by Zhenpeng
https://zplin.me/papers/DirtyCred-Zhenpeng.pdf

Patches for DirtyCred and the public release of the PoC https://github.com/Markakd/DirtyCred

CVE-2022-2585 - Linux kernel POSIX CPU timer UAF 'PoC' code source:
https://seclists.org/oss-sec/2022/q3/133

CVE-2022-2586 - Linux kernel nf_tables cross-table reference UAF 'PoC' code source:
https://seclists.org/oss-sec/2022/q3/131

Linux kernel cls_route UAF 'PoC' code source:
https://seclists.org/oss-sec/2022/q3/132
