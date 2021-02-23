# Implementacja aplikacji szyfrującej / deszyfrującej pliki z wykorzystaniem kryptografii symetrycznej

Projekt wykonany na przedmiot Wprowadzenie do cyberbezpieczeństwa.

Aplikacja została zaimplementowana w języku Python z wykorzystaniem następujących bibliotek: 
* PyQt5 - graficzny interfejs użytkownika 
* PyCrypto - algorytm szyfrujący AES oraz generowanie klucza i wektora inicjalizującego 
* base64 - kodowanie bajtów i znaków

Algorytmy symetryczne możemy podzielić na dwie główne kategorie: strumieniowe i blokowe. Do naszego projektu wybraliśmy szyfrowanie blokowe, a dokładniej algorytm AES (Advanced Encryption Standard) w różnych trybach.

Zaimplementowane tryby szyfrowania:
- Electronic codebook (ECB)
- Cipher Block Chaining (CBC)
- Counter (CTR)
- Cipher Feedback (CFB)
- Output Feedback (OFB)

## Dodatkowe informacje
1. Wszystkie operacje szyfrujące pochodzą z biblioteki Pycrypto.
2. Klucz i wektor inicjalizujący generujemy (przy każdym uruchomieniu programu) za pomocą funkcji Random.new().read(AES.block_size). Oba mają wtedy długość 128 bitów. Nie jest możliwe odszyfrowanie pliku po ponownym uruchomieniu aplikacji.
