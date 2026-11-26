/* packhead.cpp --

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>
 */

#include "conf.h"
#include "packhead.h"
#include "filter.h" // for ft->unfilter()
#include "packer.h" // for Packer::isValidFormat
#include "repair.h"

/*************************************************************************
// PackHeader
//
// We try to be able to unpack UPX 0.7x (versions 8 & 9) and at
// least to detect older versions, so this is a little bit messy.
**************************************************************************/

PackHeader::PackHeader() noexcept { reset(); }

void PackHeader::reset() noexcept {
    mem_clear(this);
    version = -1;
    format = -1;
    buf_file_start = ~0u;
    header_file_offset = ~0u;
    reconstructed_pos = -1;
    repair_alt_count = 0;
    compress_result.reset();
}

int PackHeader::set_method(const int m, const unsigned offset) { // check, then assign
    const unsigned mc = ~(0x80u << 24) & m;                      // see ph_forced_method
    const unsigned lo = 0xFF & m;
    // See packer_c.cpp for "hi bytes" in M_LZMA_003 and M_LZMA_407.
    // "hi bytes" are not allowed unless M_LZMA.
    if ((lo < M_NRV2B_LE32 || M_LZMA < lo || (M_LZMA != lo && mc != lo)) && ~0u != offset)
        throwCantPack("bad method %#x at %#x", (unsigned) m, offset);
    method = m;
    return method;
}

/*************************************************************************
// extremely simple checksum for the header itself (since version 10)
**************************************************************************/

static upx_uint8_t get_packheader_checksum(SPAN_S(const byte) buf, int blen) {
    assert(blen >= 4);
    assert(get_le32(buf) == UPX_MAGIC_LE32);
    buf += 4;
    blen -= 4;
    unsigned c = 0;
    while (blen-- > 0)
        c += *buf++;
    c %= 251;
    return (upx_uint8_t) c;
}

/*************************************************************************
//
**************************************************************************/

// Returns the size that will be generated based on version and format,
// not necessarily the size that actually is present in spoofed input.
int PackHeader::getPackHeaderSize() const {
    if (format < 0 || version < 0)
        throwInternalError("getPackHeaderSize");

    int n = 0;
    if (version <= 3) // Note: covers (version <= 0)
        n = 24;
    else if (version <= 9) {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            n = 20;
        else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
            n = 25;
        else
            n = 28;
    } else {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            n = 22;
        else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
            n = 27;
        else
            n = 32;
    }
    if (n < 20)
        throwCantUnpack("unknown header version");
    return n;
}

/*************************************************************************
// see stub/src/include/header.S
**************************************************************************/

void PackHeader::putPackHeader(SPAN_S(byte) p) const {
    // NOTE: It is the caller's responsibility to ensure the buffer p has
    // sufficient space for the header.
    assert(get_le32(p) == UPX_MAGIC_LE32);
    if (get_le32(p + 4) != UPX_MAGIC2_LE32) {
        NO_fprintf(stderr, "MAGIC2_LE32: %x %x\n", get_le32(p + 4), UPX_MAGIC2_LE32);
        throwBadLoader();
    }

    int size = 0;
    upx_uint8_t old_chksum = 0;

    // the new variable length header
    if (format < 128) { // little endian
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS) {
            size = 22;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le16(p + 16, u_len);
            set_le16(p + 18, c_len);
            p[20] = (byte) filter;
        } else if (format == UPX_F_DOS_EXE) {
            size = 27;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le24(p + 16, u_len);
            set_le24(p + 19, c_len);
            set_le24(p + 22, u_file_size);
            p[25] = (byte) filter;
        } else if (format == UPX_F_DOS_EXEH) {
            throwInternalError("invalid format");
        } else {
            size = 32;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le32(p + 16, u_len);
            set_le32(p + 20, c_len);
            set_le32(p + 24, u_file_size);
            p[28] = (byte) filter;
            p[29] = (byte) filter_cto;
            assert(n_mru == 0 || (n_mru >= 2 && n_mru <= 256));
            p[30] = (byte) (n_mru ? n_mru - 1 : 0);
        }
        set_le32(p + 8, u_adler);
        set_le32(p + 12, c_adler);
    } else { // big endian
        size = 32;
        old_chksum = get_packheader_checksum(p, size - 1);
        set_be32(p + 8, u_len);
        set_be32(p + 12, c_len);
        set_be32(p + 16, u_adler);
        set_be32(p + 20, c_adler);
        set_be32(p + 24, u_file_size);
        p[28] = (byte) filter;
        p[29] = (byte) filter_cto;
        assert(n_mru == 0 || (n_mru >= 2 && n_mru <= 256));
        p[30] = (byte) (n_mru ? n_mru - 1 : 0);
    }

    p[4] = (byte) version;
    p[5] = (byte) format;
    p[6] = (byte) method;
    p[7] = (byte) level;

    // header_checksum
    assert(size == getPackHeaderSize());
    // check old header_checksum
    if (p[size - 1] != 0) {
        if (p[size - 1] != old_chksum) {
            // printf("old_checksum: %d %d\n", p[size - 1], old_chksum);
            throwBadLoader();
        }
    }
    // store new header_checksum
    p[size - 1] = get_packheader_checksum(p, size - 1);
}

/*************************************************************************
//
**************************************************************************/

void PackHeader::decodeStrictAt(SPAN_S(const byte) p, int blen) {
    if (blen < 20)
        throwCantUnpack("header corrupted 1");

    version = p[4];
    format = p[5];
    method = p[6];
    level = p[7];
    filter_cto = 0;

    if (opt->debug.debug_level) {
        fprintf(stderr, "  decodePackHeaderFromBuf  version=%d  format=%d  method=%d  level=%d\n",
                version, format, method, level);
    }
    if (!Packer::isValidFormat(format))
        throwCantUnpack("unknown format %d", format);

    //
    // decode the new variable length header
    //

    int off_filter = 0;
    if (format < 128) {
        u_adler = get_le32(p + 8);
        c_adler = get_le32(p + 12);
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS) {
            u_len = get_le16(p + 16);
            c_len = get_le16(p + 18);
            u_file_size = u_len;
            off_filter = 20;
        } else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH) {
            if (blen < 25)
                throwCantUnpack("header corrupted 6");
            u_len = get_le24(p + 16);
            c_len = get_le24(p + 19);
            u_file_size = get_le24(p + 22);
            off_filter = 25;
        } else {
            if (blen < 31)
                throwCantUnpack("header corrupted 7");
            u_len = get_le32(p + 16);
            c_len = get_le32(p + 20);
            u_file_size = get_le32(p + 24);
            off_filter = 28;
            filter_cto = p[29];
            n_mru = p[30] ? 1 + p[30] : 0;
        }
    } else {
        if (blen < 31)
            throwCantUnpack("header corrupted 8");
        u_len = get_be32(p + 8);
        c_len = get_be32(p + 12);
        u_adler = get_be32(p + 16);
        c_adler = get_be32(p + 20);
        u_file_size = get_be32(p + 24);
        off_filter = 28;
        filter_cto = p[29];
        n_mru = p[30] ? 1 + p[30] : 0;
    }

    if (version >= 10) {
        if (blen < off_filter + 1)
            throwCantUnpack("header corrupted 9");
        filter = p[off_filter];
    } else if ((level & 128) == 0) {
        filter = 0;
    } else {
        // convert old flags to new filter id
        level &= 127;
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            filter = 0x06;
        else
            filter = 0x26;
    }
    level &= 15;

    //
    // now some checks
    //

    if (version == 0xff)
        throwCantUnpack("cannot unpack UPX ;-)");
    // check header_checksum
    if (version >= 10) {
        int size = getPackHeaderSize(); // expected; based on format and version
        if (size > blen || p[size - 1] != get_packheader_checksum(p, size - 1))
            throwCantUnpack("header corrupted 3");
    }
    if (c_len < 2 || u_len < 2 || !mem_size_valid_bytes(c_len) || !mem_size_valid_bytes(u_len))
        throwCantUnpack("header corrupted 4");

    //
    // success
    //
}

/*************************************************************************
// tolerant recovery for deformed / header-damaged UPX shells
**************************************************************************/

// Canonicalness score for a decoded hypothesis; lower is better.
static int repair_penalty(const PackHeader &t, const byte *raw,
                          const upx_repair::HeaderCandidate &c, bool stored_checksum_used,
                          int variant_kind, int solved_pos) {
    int pen = 0;
    (void) stored_checksum_used;
    // Prefer, in order: untouched valid header (kind 0), checksum-byte
    // rebuild (kind 1, does not invent field values), speculative single-byte
    // reconstruction (kind 2) which the Adler/length oracles confirm later.
    if (variant_kind == 0)
        pen -= 60;
    else if (variant_kind == 1)
        pen -= 50;
    // modern UPX headers use versions 10..14; wild values are usually
    // checksum-equation side effects at unrelated positions
    if (t.version > 14)
        pen += 400;
    else if (t.version < 9)
        pen += 60;
    else if (t.version >= 13 && t.version <= 14)
        pen -= 8;
    // for version >= 10 the high nibble of the level byte is reserved/junk
    if (t.version >= 10 && raw) {
        const int junk_bits = raw[7] & 0x70;
        pen += junk_bits * 2;
    }
    if (t.filter != 0 && !Filter::isValidFilter(t.filter))
        pen += 120;
    if (t.u_len < t.u_file_size)
        pen += 20;
    if (t.c_len > t.u_len)
        pen += 25;
    if (t.u_len > 0x40000000u || t.c_len > 0x40000000u)
        pen += 200;
    // Opaque high entropy fields: prefer not to "guess" replacement values
    // here; the Adler oracle in ph_decompress confirms the right hypothesis.
    if (variant_kind == 2 && solved_pos >= 8 && solved_pos <= 15)
        pen += 30;
    if (variant_kind == 2 && (solved_pos == 29 || solved_pos == 30))
        pen += 30;
    // prefer the highest ranked fuzzy location
    pen += (200 - c.score) / 4;
    return pen;
}

bool PackHeader::loadRepairAlt(int idx) {
    if (idx < 0 || idx >= repair_alt_count)
        return false;
    byte saved_raw[REPAIR_MAX_ALT][32];
    int saved_size[REPAIR_MAX_ALT];
    const int saved_count = repair_alt_count;
    memcpy(saved_raw, repair_alt_raw, sizeof(saved_raw));
    memcpy(saved_size, repair_alt_size, sizeof(saved_size));

    const unsigned save_boff = buf_offset;
    const unsigned save_start = buf_file_start;
    const unsigned save_abs = header_file_offset;
    const bool save_recovery = recovery_used;
    const unsigned save_saved_u = saved_u_adler;
    const unsigned save_saved_c = saved_c_adler;

    byte target[32];
    const int target_size = saved_size[idx];
    memcpy(target, saved_raw[idx], target_size);

    reset();
    saved_u_adler = save_saved_u ? save_saved_u : upx_adler32(nullptr, 0);
    saved_c_adler = save_saved_c ? save_saved_c : upx_adler32(nullptr, 0);
    try {
        decodeStrictAt(SPAN_S_MAKE(const byte, target, target_size), target_size);
    } catch (const Throwable &) {
        return false;
    }
    buf_offset = save_boff;
    buf_file_start = save_start;
    header_file_offset = save_abs;
    memcpy(repair_alt_raw, saved_raw, sizeof(saved_raw));
    memcpy(repair_alt_size, saved_size, sizeof(saved_size));
    repair_alt_count = saved_count;
    recovery_used = save_recovery;
    return true;
}

bool PackHeader::decodePackHeaderFromBuf(SPAN_S(const byte) buf_span, int blen) {
    const byte *buf = raw_bytes(buf_span, blen);
    auto &diag = upx_repair::diag();
    const bool tolerant = (!opt || opt->repair_enabled);
    // Packer initializes the chained-Adler seed before probing; reset() in
    // the recovery path must not lose it.
    const unsigned keep_saved_u = saved_u_adler ? saved_u_adler : upx_adler32(nullptr, 0);
    const unsigned keep_saved_c = saved_c_adler ? saved_c_adler : upx_adler32(nullptr, 0);

    // ---- pass 1: exact "UPX!" magic, original strict decoder ----
    int boff = find_le32(buf, blen, UPX_MAGIC_LE32);
    if (boff >= 0) {
        try {
            decodeStrictAt(SPAN_S_MAKE(const byte, buf + boff, blen - boff), blen - boff);
            buf_offset = boff;
            checksums_authentic = true;
            // keep the intact header as alternate 0 for the adler oracle
            repair_alt_count = 0;
            if (blen - boff >= 32) {
                repair_alt_size[0] = 32;
                memcpy(repair_alt_raw[0], buf + boff, 32);
                repair_alt_count = 1;
            }
            return true;
        } catch (const Throwable &e) {
            diag.add(upx_repair::DIAG_INFO, upx_repair::NO_OFFSET, "strict-reject",
                     "exact UPX! in scan window at offset %#x rejected: %s", (unsigned) boff,
                     e.getMsg() ? e.getMsg() : "error");
            if (!tolerant)
                throw;
        }
    } else if (!tolerant) {
        return false;
    }

    // ---- pass 2: fuzzy / structural candidate scan ----
    upx_repair::HeaderCandidate cands[24];
    int nc = upx_repair::find_header_candidates(buf, blen, cands, 24);
    diag.add(upx_repair::DIAG_INFO, upx_repair::NO_OFFSET, "candidate-scan",
             "%d structural UPX header candidate(s) in %d-byte window", nc, blen);
    if (nc == 0)
        return false;

    int best_penalty = INT_MAX;
    int best_cand = -1;
    byte best_raw[32];
    int best_size = 0;
    bool best_rebuilt = false;
    int best_solved_pos = -1;

    repair_alt_count = 0;

    // try the ranked candidates; collect every checksum-valid hypothesis of
    // the best candidate so decompression can use the Adler-32 oracles
    for (int ci = 0; ci < nc; ci++) {
        const upx_repair::HeaderCandidate &c = cands[ci];
        const int o = c.boff;
        const int s = c.hdr_size;
        if (s < 20 || o + s > blen)
            continue;
        const byte *cp = buf + o;

        struct Variant {
            byte data[32];
            int kind; // 0 as-is, 1 rebuild, 2 solve
            int pos;
        };
        Variant vars[64];
        int nv = 0;

        // as-is
        if (nv < 64) {
            memcpy(vars[nv].data, cp, s);
            vars[nv].kind = 0;
            vars[nv].pos = -1;
            nv++;
        }
        // checksum byte rebuild
        if (nv < 64) {
            memcpy(vars[nv].data, cp, s);
            vars[nv].data[s - 1] = upx_repair::packheader_checksum(vars[nv].data, s);
            vars[nv].kind = 1;
            vars[nv].pos = s - 1;
            nv++;
        }
        // checksum-equation single byte reconstruction
        for (int pos = 4; pos < s - 1 && nv < 64; pos++) {
            int vals[4];
            int nval = upx_repair::solve_single_byte_values(cp, s, pos, vals, 4);
            for (int j = 0; j < nval && nv < 64; j++) {
                memcpy(vars[nv].data, cp, s);
                vars[nv].data[pos] = (byte) vals[j];
                vars[nv].kind = 2;
                vars[nv].pos = pos;
                nv++;
            }
        }

        int cand_accepted = 0;
        for (int vi = 0; vi < nv; vi++) {
            // The header checksum helper asserts the magic constant, and a
            // deformed magic is exactly what we repair; restore it in every
            // hypothesis before strict decoding.
            memcpy(vars[vi].data, "UPX!", 4);
            PackHeader t;
            t.reset();
            try {
                t.decodeStrictAt(SPAN_S_MAKE(const byte, vars[vi].data, s), s);
            } catch (const Throwable &) {
                continue;
            }
            // hard structural validation (mirrors Packer::getPackHeader)
            if (t.version <= 0 || t.version >= 0xff)
                continue;
            if (t.c_len < 2 || t.u_len < 2)
                continue;
            if (!mem_size_valid_bytes(t.c_len) || !mem_size_valid_bytes(t.u_len))
                continue;
            if (!Packer::isValidCompressionMethod(t.method))
                continue;

            const bool stored_used = vars[vi].kind != 1;
            const int solved_pos = vars[vi].kind == 2 ? vars[vi].pos : -1;
            const int pen = repair_penalty(t, vars[vi].data, c, stored_used, vars[vi].kind,
                                           solved_pos);

            // store as alternate for the adler oracle
            if (repair_alt_count < REPAIR_MAX_ALT && s <= 32) {
                repair_alt_size[repair_alt_count] = s;
                memcpy(repair_alt_raw[repair_alt_count], vars[vi].data, s);
                repair_alt_count++;
            }
            cand_accepted++;

            if (pen < best_penalty) {
                best_penalty = pen;
                best_cand = ci;
                best_size = s;
                best_rebuilt = vars[vi].kind == 1;
                best_solved_pos = vars[vi].kind == 2 ? vars[vi].pos : -1;
                memcpy(best_raw, vars[vi].data, s);
            }
        }

        // the top-ranked candidate that yields valid hypotheses is enough to
        // collect alternates from; but keep scanning if nothing accepted yet
        if (cand_accepted > 0 && ci == 0)
            break;
    }

    if (best_cand < 0) {
        // An exact magic existed but every repair failed: leave a precise
        // reason and let the format frontend decide how to surface it.
        if (boff >= 0)
            diag.add(upx_repair::DIAG_FAIL, upx_repair::NO_OFFSET, "header-unrecoverable",
                     "found 'UPX!' at window offset %#x but none of %d structural repair"
                     " hypotheses passed version/format/method/length checks",
                     (unsigned) boff, nc);
        return false;
    }

    // preserve collected alternates across reset()
    byte saved_alts[REPAIR_MAX_ALT][32];
    int saved_alt_sizes[REPAIR_MAX_ALT];
    const int saved_alt_count = repair_alt_count < REPAIR_MAX_ALT ? repair_alt_count
                                                                 : REPAIR_MAX_ALT;
    memcpy(saved_alts, repair_alt_raw, sizeof(saved_alts));
    memcpy(saved_alt_sizes, repair_alt_size, sizeof(saved_alt_sizes));

    // commit best hypothesis
    reset();
    saved_u_adler = keep_saved_u;
    saved_c_adler = keep_saved_c;
    decodeStrictAt(SPAN_S_MAKE(const byte, best_raw, best_size), best_size);
    buf_offset = cands[best_cand].boff;
    recovery_used = true;
    magic_restored = cands[best_cand].magic_dist > 0;
    checksum_byte_rebuilt = best_rebuilt;
    byte_reconstructed = best_solved_pos >= 0;
    reconstructed_pos = best_solved_pos;
    // If we rebuilt the checksum byte ourselves, header fields (including the
    // Adler values) are only tentatively trusted; the decompression stage has
    // the final say via the Adler oracles.
    checksums_authentic = !best_rebuilt;

    if (magic_restored)
        diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "magic-fuzzy",
                 "UPX magic located by fuzzy scan at window offset %#x (hamming distance %d)",
                 (unsigned) buf_offset, cands[best_cand].magic_dist);
    if (byte_reconstructed)
        diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "byte-reconstructed",
                 "header byte[%d] reconstructed via checksum equation using original stored"
                 " checksum", reconstructed_pos);
    if (checksum_byte_rebuilt)
        diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "checksum-rebuilt",
                 "header checksum byte recomputed; Adler fields treated as untrusted until"
                 " decompression confirms them");
    if (!magic_restored && !byte_reconstructed && !checksum_byte_rebuilt)
        diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "fuzzy-located",
                 "header located via structural scan at window offset %#x",
                 (unsigned) buf_offset);

    // restore alternates; make sure the chosen header is present as well
    repair_alt_count = saved_alt_count;
    memcpy(repair_alt_raw, saved_alts, sizeof(saved_alts));
    memcpy(repair_alt_size, saved_alt_sizes, sizeof(saved_alt_sizes));
    repair_alt_size[0] = best_size;
    memcpy(repair_alt_raw[0], best_raw, best_size);
    if (repair_alt_count <= 0)
        repair_alt_count = 1;
    return true;
}

/*************************************************************************
// ph method util
**************************************************************************/

bool ph_is_forced_method(int method) noexcept { // predicate
    return (method >> 24) == -0x80;
}

int ph_force_method(int method) noexcept { // mark as forced
    return method | (0x80u << 24);
}

int ph_forced_method(int method) noexcept { // extract the forced method
    if (ph_is_forced_method(method))
        method &= ~(0x80u << 24);
    assert_noexcept(method > 0);
    return method;
}

bool ph_skipVerify(const PackHeader &ph) noexcept {
    if (M_IS_DEFLATE(ph.method))
        return false;
    if (M_IS_LZMA(ph.method))
        return false;
    if (ph.level > 1)
        return false;
    return true;
}

/*************************************************************************
// ph decompress util
**************************************************************************/

// Find a stored header hypothesis whose Adler field matches the computed
// checksum and whose decompression parameters are compatible with the buffers
// already allocated by the caller.
static int repair_find_alt_by_adler(const PackHeader &ph, bool compressed_side,
                                    unsigned actual_adler, bool filter_matters) {
    for (int i = 0; i < ph.repair_alt_count; i++) {
        PackHeader t;
        t.reset();
        if (ph.repair_alt_size[i] < 20)
            continue;
        try {
            t.decodeStrictAt(
                SPAN_S_MAKE(const byte, ph.repair_alt_raw[i], ph.repair_alt_size[i]),
                ph.repair_alt_size[i]);
        } catch (const Throwable &) {
            continue;
        }
        if (compressed_side ? (t.c_adler != actual_adler) : (t.u_adler != actual_adler))
            continue;
        if (t.method != ph.method || t.u_len != ph.u_len || t.c_len != ph.c_len)
            continue;
        if (filter_matters && (t.filter != ph.filter || t.filter_cto != ph.filter_cto))
            continue;
        return i;
    }
    return -1;
}

void ph_decompress(PackHeader &ph, SPAN_P(const byte) in, SPAN_P(byte) out, bool verify_checksum,
                   Filter *ft) {
    auto &diag = upx_repair::diag();
    const bool tolerant = (!opt || opt->repair_enabled);
    bool checksum_gate = verify_checksum;

    // verify checksum of compressed data
    if (verify_checksum) {
        unsigned adler = upx_adler32(raw_bytes(in, ph.c_len), ph.c_len, ph.saved_c_adler);
        if (adler != ph.c_adler) {
            diag.add(upx_repair::DIAG_INFO, upx_repair::NO_OFFSET, "c-adler-mismatch",
                     "header c_adler=%08x computed=%08x over %u bytes", ph.c_adler, adler,
                     ph.c_len);
            int ai = tolerant ? repair_find_alt_by_adler(ph, true, adler, ft != nullptr) : -1;
            if (ai >= 0 && ph.loadRepairAlt(ai)) {
                diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "alt-cadler",
                         "selected reconstructed header hypothesis #%d whose c_adler matches the"
                         " compressed stream",
                         ai);
            } else if (tolerant && ph.recovery_used) {
                diag.add(upx_repair::DIAG_WARN, upx_repair::NO_OFFSET, "cadler-unverified",
                         "c_adler mismatch (%08x != header %08x) and no header hypothesis matches;"
                         " treating Adler fields as damaged, continuing without checksum gate",
                         adler, ph.c_adler);
                checksum_gate = false;
            } else {
                throwCantUnpack("compressed-stream checksum mismatch: header c_adler=%08x but"
                                " computed %08x over %u compressed bytes -- the compressed data"
                                " is corrupted or truncated (not just a damaged header)",
                                ph.c_adler, adler, ph.c_len);
            }
        }
    }

    // decompress
    if (ph.u_len < ph.c_len)
        throwCantUnpack("header corrupted: u_len=%u is smaller than c_len=%u", ph.u_len,
                        ph.c_len);
    unsigned new_len = ph.u_len;
    int r = upx_decompress(raw_bytes(in, ph.c_len), ph.c_len, raw_bytes(out, ph.u_len), &new_len,
                           ph_forced_method(ph.method), &ph.compress_result);
    if (r == UPX_E_OUT_OF_MEMORY)
        throwOutOfMemoryException();
    if (r == UPX_E_OK && new_len != ph.u_len && tolerant && ph.recovery_used) {
        // a corrupted u_len header byte may have selected the wrong primary
        // hypothesis; let the actual decoded length choose an alternate
        int li = -1;
        for (int i = 0; i < ph.repair_alt_count && li < 0; i++) {
            PackHeader t;
            t.reset();
            try {
                t.decodeStrictAt(
                    SPAN_S_MAKE(const byte, ph.repair_alt_raw[i], ph.repair_alt_size[i]),
                    ph.repair_alt_size[i]);
            } catch (const Throwable &) {
                continue;
            }
            if (t.u_len == new_len && t.c_len == ph.c_len && t.method == ph.method)
                li = i;
        }
        if (li >= 0 && ph.loadRepairAlt(li)) {
            diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "alt-ulen",
                     "corrected u_len to %u using actual decompressed length via hypothesis #%d",
                     new_len, li);
        } else {
            throwCantUnpack("header u_len=%u does not match decompressed length %u and no header"
                            " hypothesis resolves it",
                            ph.u_len, new_len);
        }
    } else if (r != UPX_E_OK || new_len != ph.u_len) {
        throwCantUnpack("decompression failed: method=%d errcode=%d decoded_length=%u expected=%u"
                        " -- compressed stream is corrupt or truncated",
                        ph_forced_method(ph.method), r, new_len, ph.u_len);
    }

    // verify checksum of decompressed data
    if (verify_checksum) {
        if (ft)
            ft->unfilter(out, ph.u_len);
        unsigned adler = upx_adler32(raw_bytes(out, ph.u_len), ph.u_len, ph.saved_u_adler);
        if (checksum_gate && adler != ph.u_adler) {
            diag.add(upx_repair::DIAG_INFO, upx_repair::NO_OFFSET, "u-adler-mismatch",
                     "header u_adler=%08x computed=%08x over %u bytes", ph.u_adler, adler,
                     ph.u_len);
            int ai = tolerant ? repair_find_alt_by_adler(ph, false, adler, ft != nullptr) : -1;
            if (ai >= 0 && ph.loadRepairAlt(ai)) {
                diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "alt-uadler",
                         "selected reconstructed header hypothesis #%d whose u_adler matches the"
                         " decompressed data",
                         ai);
            } else if (tolerant && ph.recovery_used) {
                diag.add(upx_repair::DIAG_WARN, upx_repair::NO_OFFSET, "uadler-unverified",
                         "u_adler mismatch (%08x != header %08x); decompression itself succeeded"
                         " but output integrity cannot be proven",
                         adler, ph.u_adler);
            } else {
                throwCantUnpack("decompressed-data checksum mismatch: header u_adler=%08x but"
                                " computed %08x over %u bytes -- decompressed content is corrupt"
                                " or the header checksum field was tampered",
                                ph.u_adler, adler, ph.u_len);
            }
        } else if (!checksum_gate) {
            // we intentionally ran without the Adler gate; still try to
            // upgrade the result by finding a matching header hypothesis
            int ai = tolerant ? repair_find_alt_by_adler(ph, false, adler, ft != nullptr) : -1;
            if (ai >= 0 && ph.loadRepairAlt(ai))
                diag.add(upx_repair::DIAG_REPAIRED, upx_repair::NO_OFFSET, "alt-uadler-late",
                         "unverified recovery confirmed by u_adler via header hypothesis #%d", ai);
        }
    }
}

/*************************************************************************
// ph overlapping decompression util
**************************************************************************/

bool ph_testOverlappingDecompression(const PackHeader &ph, const byte *buf, const byte *tbuf,
                                     unsigned overlap_overhead) {
    if (ph.c_len >= ph.u_len)
        return false;

    assert((int) overlap_overhead >= 0);
    assert((int) (ph.u_len + overlap_overhead) >= 0);
    const int method = ph_forced_method(ph.method);

    // Because upx_test_overlap() does not use the asm_fast decompressor
    // we must account for extra 3 bytes that asm_fast does use,
    // or else we may fail at runtime decompression.
    unsigned extra = 0;
    if (M_IS_NRV2B(method) || M_IS_NRV2D(method) || M_IS_NRV2E(method))
        extra = 3;
    if (overlap_overhead <= 4 + extra) // don't waste time here
        return false;
    overlap_overhead -= extra;

    unsigned src_off = ph.u_len + overlap_overhead - ph.c_len;
    unsigned new_len = ph.u_len;
    int r = upx_test_overlap(buf - src_off, tbuf, src_off, ph.c_len, &new_len, method,
                             &ph.compress_result);
    if (r == UPX_E_OUT_OF_MEMORY)
        throwOutOfMemoryException();
    return (r == UPX_E_OK && new_len == ph.u_len);
}

/* vim:set ts=4 sw=4 et: */
