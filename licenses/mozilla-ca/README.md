# Mozilla CA certificate source provenance

The runtime trust bundle is generated from Mozilla NSS certificate data by Alpine Linux's `ca-certificates` package. This source file is distributed in the project image to preserve the MPL 2.0 source-form availability notice for the data bundle.

- Alpine package: `ca-certificates-bundle` `20261020-r0`, Alpine v3.22, x86_64.
- Upstream source archive: `https://gitlab.alpinelinux.org/alpine/ca-certificates/-/archive/20261020/ca-certificates-20261020.tar.bz2`
- Source archive SHA-512: `d28eb01751b1a914ffb5d8cb99e662f0a35a95148c21dcf98de1ab3108b54db9714a99472d07715023867f4f76a21f2a79a2bc1c7e9876ce5167fdd865ad2dd7`
- Included source file: `certdata.txt` from that archive. It contains the MPL 2.0 source notice.
- Package license metadata: `MPL-2.0 AND MIT`; both license texts are included in this directory. The MIT notice is retained from the Alpine package's MIT-licensed `c_rehash.c` component; that code itself is not copied into the AWG Switcher image. Terms applicable to each included CA certificate remain subject to final package/image review.

No certificate data was edited by AWG Switcher.
