# 20 deformed UPX samples - unpack success comparison

- Baseline UPX: `/home/dev/feedback/uid38857/deform/upx-baseline`
- Enhanced UPX: `/home/dev/feedback/uid38857/build-enhanced/upx`
- Correctness criterion: exit code 0 and sha256 identical to the known-good unpacked file (`236166bbe2d8450b...`)

**Success rate: baseline 0/20 (0%) -> enhanced 19/20 (95%)**

| # | deformation | class | baseline | enhanced | enhanced specific reason on failure |
|---|-------------|-------|:--------:|:--------:|---------------------------------------|
| 01 | `magic_bitflip` | magic | ❌ | ✅ |  |
| 02 | `magic_lowercase` | magic | ❌ | ✅ |  |
| 03 | `magic_zeroed` | magic | ❌ | ✅ |  |
| 04 | `magic_replaced` | magic | ❌ | ✅ |  |
| 05 | `magic_xor_encoded` | magic | ❌ | ✅ |  |
| 06 | `hdr_checksum_zero` | header-checksum | ❌ | ✅ |  |
| 07 | `hdr_checksum_ff` | header-checksum | ❌ | ✅ |  |
| 08 | `level_junk_bit` | header-field | ❌ | ✅ |  |
| 09 | `version_poke` | header-field | ❌ | ✅ |  |
| 10 | `format_poke` | header-field | ❌ | ✅ |  |
| 11 | `method_poke` | header-field | ❌ | ✅ |  |
| 12 | `uadler_byte` | header-field | ❌ | ✅ |  |
| 13 | `cadler_byte` | header-field | ❌ | ✅ |  |
| 14 | `ulen_byte` | header-field | ❌ | ✅ |  |
| 15 | `both_adlers_multibyte` | header-field | ❌ | ✅ |  |
| 16 | `rename_upx0` | section-name | ❌ | ✅ |  |
| 17 | `rename_all_sections` | section-name | ❌ | ✅ |  |
| 18 | `rename_and_magic` | combined | ❌ | ✅ |  |
| 19 | `section_names_zeroed` | section-name | ❌ | ✅ |  |
| 20 | `payload_destroyed` | negative-control | ❌ | ❌ | compressed-stream checksum mismatch: header c_adler=09716e6c but computed cf516f0d over 77414 compressed bytes -- the compressed data is corrupted or truncat... |

## Baseline failure reasons (generic messages)

- **01 magic_bitflip**: file is modified/hacked/protected; take care!!!
- **02 magic_lowercase**: file is modified/hacked/protected; take care!!!
- **03 magic_zeroed**: file is modified/hacked/protected; take care!!!
- **04 magic_replaced**: file is modified/hacked/protected; take care!!!
- **05 magic_xor_encoded**: file is modified/hacked/protected; take care!!!
- **06 hdr_checksum_zero**: header corrupted 3
- **07 hdr_checksum_ff**: header corrupted 3
- **08 level_junk_bit**: header corrupted 3
- **09 version_poke**: header corrupted 3
- **10 format_poke**: unknown format 70
- **11 method_poke**: header corrupted 3
- **12 uadler_byte**: header corrupted 3
- **13 cadler_byte**: header corrupted 3
- **14 ulen_byte**: header corrupted 3
- **15 both_adlers_multibyte**: header corrupted 3
- **16 rename_upx0**: file is modified/hacked/protected; take care!!!
- **17 rename_all_sections**: file is modified/hacked/protected; take care!!!
- **18 rename_and_magic**: file is modified/hacked/protected; take care!!!
- **19 section_names_zeroed**: file is modified/hacked/protected; take care!!!
- **20 payload_destroyed**: upx-baseline: /home/dev/feedback/uid38857/deform/samples/20_payload_destroyed.exe: Exception: checksum error

## Enhanced failure detail

### 20 payload_destroyed
```
compressed-stream checksum mismatch: header c_adler=09716e6c but computed cf516f0d over 77414 compressed bytes -- the compressed data is corrupted or truncated (not just a damaged header)

, header_size=32)
    magic bytes   : 57 6f ea 93 ('Wo..'), hamming-distance=4
    version=47 format=252 (unknown/other) method=234 level=3
    hdr checksum  : stored=0x52 computed=0x52 -> VALID
    repair action : restore magic constant to 'UPX!'

  candidate #3 at file offset 0x4d7 (score=105, header_size=32)
    magic bytes   : d0 e6 fc 08 ('....'), hamming-distance=4
    version=51 format=158 (unknown/other) method=231 level=9
    hdr checksum  : stored=0x10 computed=0x10 -> VALID
    repair action : restore magic constant to 'UPX!'

  candidate #4 at file offset 0x481 (score=100, header_size=32)
    magic bytes   : cf f3 3c ef ('..<.'), hamming-distance=4
    version=14 format=46 (unknown/other) method=6 level=8
    u_len=1592188098 c_len=1009783036 u_file_size=2114909135
    hdr checksum  : stored=0x6c computed=0x78 -> MISMATCH
    repair action : restore magic constant to 'UPX!'
    repair action : recompute header checksum byte to 0x78
    repair option : checksum equation reconstructs header byte[5] (format) as 34 (original stored checksum stays authentic)

  candidate #5 at file offset 0x3e2 (score=90, header_size=28)
    magic bytes   : 58 21 0d 09 ('X!..'), hamming-distance=4
    version=8 format=8 (unknown/other) method=7 level=5
    u_len=778436612 c_len=2650800129 u_file_size=187039748
    hdr checksum  : stored=0x0b computed=0xe4 -> MISMATCH
    repair action : restore magic constant to 'UPX!'
    repair action : recompute header checksum byte to 0xe4
    repair option : checksum equation reconstructs header byte[4] (version) as 42 (original stored checksum stays authentic)

  VERDICT: UPX shell detected but a specific unrecoverable condition was found; see SPECIFIC FAILURE above.

WARNING: this is an unstable beta version - use for testing only! Really.
```
