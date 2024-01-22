# SAM Parser

## About

It's a little tool written in Go that should be able to extract credentials from the classic Windows hives (SAM, SECURITY, and SYSTEM), and eventually NTDS too.

## Author

Robert C. Raducioiu (rbct)

## References:

- <https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/>
- <https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/reg.rb>
- <https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py>
- <https://github.com/Velocidex/regparser/blob/bbc758cbd18b/regparser_gen.go>
- <https://www.rapid7.com/blog/post/2012/01/16/adventures-in-the-windows-nt-registry-a-step-into-the-world-of-forensics-and-ig/>
- <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md>
- <https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_LOCAL_MACHINE/SAM/SAM/Domains/Account/Users/000001F4/index>
- <https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm>
- <https://github.com/vphpersson/msdsalgs/blob/ee7525e50ffcff4574371baac226e578078abc03/msdsalgs/crypto.py>
- <https://docs.python.org/3/library/struct.html>
- <https://github.com/C-Sto/gosecretsdump/blob/v0.3.1/pkg/samreader/samreader.go>

