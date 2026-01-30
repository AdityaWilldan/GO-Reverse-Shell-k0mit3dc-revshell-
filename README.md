
# K0M1T3DC RAT(Remote Acess Trojan)
⚠️ DISCLAIMER
HANYA UNTUK PENDIDIKAN DAN RESEARCH DALAM LINGKUNGAN TERKONTROL
Tools ini dibuat semata-mata untuk tujuan pembelajaran dalam bidang keamanan siber.
Dilarang keras menggunakan untuk aktivitas ilegal atau tanpa izin.

Project Windows RAT ini berbasis Go ini dikembangkan oleh Komunitas K0m1t3dc(ctf team from univmandiri subang) sebagai alat pembelajaran untuk memahami teknik malware development, detection, dan mitigation dalam konteks defensive cybersecurity research.

Kode ini belum sepenuhnya powerfull dan masih menggunakan reverse shell plaintext, implementasi evasion yang basic, hardcoded C2 via ngrok, dan berbagai incomplete features yang sengaja dibiarkan untuk pengembangan lebih lanjut.
## Screenshots

![App Screenshot](https://drive.google.com/file/d/1mSnt_armLlpA0BZSct9WClTQJtoFucoV)

## Documentation

[Documentation](https://github.com/AdityaWilldan/GO-Reverse-Shell-k0mit3dc-revshell-/blob/main/README.md)

clone repo ini

```bash
  git clone https://github.com/AdityaWilldan/GO-Reverse-Shell-k0mit3dc-revshell-.git
  cd /GO-Reverse-Shell-k0mit3dc-revshell
```

## Installation

install golang 
```bash
 for windows: https://go.dev/dl/
 for linux: 
 sudo apt update
 sudo apt install golang-go
```
set GOPATH
```bash
windows: setx GOPATH %USERPROFILE%\go

```

Install Dependencies
```bash
go get github.com/moutend/go-hook
go get golang.org/x/sys/windows
go get golang.org/x/sys/windows/registry

```


