# GimliManaged
A C# Port (.Net Core 3) of the Gimli lightweight AEAD/Hash crypto scheme.

NIST's Leightweight Cryptography Project: https://csrc.nist.gov/Projects/lightweight-cryptography/  
Source: https://gimli.cr.yp.to/

Daniel J. Bernstein, University of Illinois at Chicago  
Stefan Kölbl, Technical University of Denmark  
Stefan Lucks, Bauhaus-Universität Weimar  
Pedro Maat Costa Massolino, Radboud University  
Florian Mendel, Graz University of Technology  
Kashif Nawaz, Université Catholique de Louvain  
Tobias Schneider, Ruhr-University Bochum  
Peter Schwabe, Radboud University  
François-Xavier Standaert, Université Catholique de Louvain  
Yosuke Todo, NTT Secure Platform Laboratories  
Benoît Viguier, Radboud University  
Dustin Sparks, Leidos Innovations Corp. (*this port only*, and this work is based directly on the original source implementation by the above as submitted to NIST in Round 2)

From the authors: *"Gimli is a 384-bit permutation designed to achieve high security with high performance across a broad range of platforms, including 64-bit Intel/AMD server CPUs, 64-bit and 32-bit ARM smartphone CPUs, 32-bit ARM microcontrollers, 8-bit AVR microcontrollers, FPGAs, ASICs without side-channel protection, and ASICs with side-channel protection."*
