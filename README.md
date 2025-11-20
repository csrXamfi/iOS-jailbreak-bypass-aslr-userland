# iOS-jailbreak-bypass-aslr-userland

```bash
iPhone-csrXamfi:~/asm mobile% clang-16 -isysroot /var/jb/var/mobile/sdks/iPhoneOS16.5.sdk ios_aslr_bypass.c -o ios_aslr_bypass
iPhone-csrXamfi:~/asm mobile% ldid -Sent.plist
iPhone-csrXamfi:~/asm mobile% sudo ./final
[sudo] password for mobile: 
Enter offset to function (nm -gU your_binary): 0
Enter PID: 56
[+] ASLR slide for /usr/libexec/amfid: 0x4358000
Your address: 0x4358000
```
