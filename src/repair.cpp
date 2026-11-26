/* repair.cpp -- tolerant recognition and repair of deformed UPX shells */

#include "conf.h"
#include "repair.h"
#include "packer.h" // Packer::isValidFormat / isValidCompressionMethod

#include <stdio.h>
#include <string.h>

namespace upx_repair {

/*************************************************************************
// diagnostic trail
**************************************************************************/

static DiagLog g_diag;
static char g_current_name[1024];

DiagLog &diag() noexcept { return g_diag; }

void DiagLog::clear() noexcept { count = 0; }

void DiagLog::add(int level, unsigned offset, const char *code, const char *fmt, ...) noexcept {
    if (count >= MAX_ENTRIES)
        return;
    DiagEntry &e = entries[count++];
    e.level = level;
    e.offset = offset;
    if (code) {
        snprintf(e.code, sizeof(e.code), "%s", code ? code : "");
    }
    e.message[0] = 0;
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        upx_safe_vsnprintf(e.message, sizeof(e.message), fmt, ap);
        va_end(ap);
    }
}

void reset_for_file(const char *name) noexcept {
    g_diag.clear();
    g_current_name[0] = 0;
    if (name)
        snprintf(g_current_name, sizeof(g_current_name), "%s", name ? name : "");
}

const char *current_name() noexcept { return g_current_name[0] ? g_current_name : nullptr; }

static bool should_print_level(int level) noexcept {
    if (!opt)
        return level >= DIAG_REPAIRED;
    if (opt->repair_verbosity >= 2)
        return true;
    return level >= DIAG_REPAIRED;
}

void emit_repair_notes(const char *iname) noexcept {
    for (int i = 0; i < g_diag.size(); i++) {
        const DiagEntry &e = g_diag.at(i);
        if (e.level == DIAG_REPAIRED)
            printWarn(iname, "recovery [%s]: %s", e.code, e.message);
        else if (e.level == DIAG_WARN)
            printWarn(iname, "recovery [%s]: %s", e.code, e.message);
    }
}

void emit_failure_trail(const char *iname, bool suppress_weak) noexcept {
    // Prefer decisive FAIL entries; fall back to warnings/repaired notes.
    bool printed_any = false;
    int fail_count = 0;
    for (int i = 0; i < g_diag.size(); i++)
        if (g_diag.at(i).level == DIAG_FAIL)
            fail_count++;
    for (int i = 0; i < g_diag.size(); i++) {
        const DiagEntry &e = g_diag.at(i);
        if (e.level != DIAG_FAIL)
            continue;
        printErr(iname, "diagnosis [%s]: %s", e.code, e.message);
        printed_any = true;
    }
    if (suppress_weak && fail_count == 0)
        return;
    if (!printed_any) {
        for (int i = 0; i < g_diag.size(); i++) {
            const DiagEntry &e = g_diag.at(i);
            if (e.level == DIAG_WARN || e.level == DIAG_REPAIRED) {
                printErr(iname, "diagnosis [%s]: %s", e.code, e.message);
                printed_any = true;
            }
        }
    }
    if (opt && opt->repair_verbosity >= 2) {
        for (int i = 0; i < g_diag.size(); i++) {
            const DiagEntry &e = g_diag.at(i);
            if (e.level == DIAG_INFO && should_print_level(e.level))
                fprintf(stderr, "  [trace %s] %s\n", e.code, e.message);
        }
    }
}

/*************************************************************************
// header primitives
**************************************************************************/

const int kHeaderSizes[6] = {32, 28, 27, 25, 22, 20};

upx_uint8_t packheader_checksum(const byte *p, int hdr_size) noexcept {
    if (hdr_size < 5)
        return 0;
    unsigned c = 0;
    for (int i = 4; i < hdr_size - 1; i++)
        c += p[i];
    c %= 251;
    return (upx_uint8_t) c;
}

int magic_hamming4(const byte *p) noexcept {
    static const byte magic[4] = {'U', 'P', 'X', '!'};
    int d = 0;
    for (int i = 0; i < 4; i++)
        if (p[i] != magic[i])
            d++;
    return d;
}

bool magic_looks_like_upx(const byte *p, int max_dist) noexcept {
    return magic_hamming4(p) <= max_dist;
}

int solve_single_byte_values(const byte *p, int hdr_size, int pos, int *values,
                             int max_values) noexcept {
    if (pos < 4 || pos >= hdr_size - 1 || max_values <= 0)
        return 0;
    unsigned sum_others = 0;
    for (int i = 4; i < hdr_size - 1; i++)
        if (i != pos)
            sum_others += p[i];
    const unsigned target = p[hdr_size - 1];
    int found = 0;
    for (int v = 0; v <= 255 && found < max_values; v++) {
        if (((sum_others + (unsigned) v) % 251) == target)
            values[found++] = v;
    }
    return found;
}

static bool version_plausible(int v) noexcept { return v >= 8 && v != 0xff && v <= 64; }

static bool method_plausible(int m) noexcept {
    // raw header method byte; the strict Packer validator runs later.
    return m >= M_NRV2B_LE32 && m <= M_NRV2E_8 + 8; // generous upper bound incl. LZMA/zstd
}

// Mirror of PackHeader::getPackHeaderSize() for plausible field values.
static int expected_header_size(int version, int format) noexcept {
    if (version < 0)
        return 32;
    if (version <= 3)
        return 24;
    if (version <= 9) {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            return 20;
        if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
            return 25;
        return 28;
    }
    if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
        return 22;
    if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
        return 27;
    return 32;
}

static bool lengths_sane_le(const byte *p, int format, int hdr_size, int blen) noexcept {
    if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS) {
        unsigned u = get_le16(p + 16), c = get_le16(p + 18);
        return u >= 2 && c >= 2;
    }
    if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH) {
        unsigned u = get_le24(p + 16), c = get_le24(p + 19);
        return u >= 2 && c >= 2;
    }
    if (format < 128) {
        unsigned u = get_le32(p + 16), c = get_le32(p + 20);
        if (u < 2 || c < 2)
            return false;
        if (u > 0x7fffffffu || c > 0x7fffffffu)
            return false;
        (void) hdr_size;
        (void) blen;
        return true;
    }
    unsigned u = get_be32(p + 8), c = get_be32(p + 12);
    return u >= 2 && c >= 2 && u <= 0x7fffffffu && c <= 0x7fffffffu;
}

/*************************************************************************
// candidate scanning
**************************************************************************/

int find_header_candidates(const byte *buf, int len, HeaderCandidate *out, int max_out) noexcept {
    if (!buf || len < 20 || !out || max_out <= 0)
        return 0;

    // simple fixed scratch of ranked candidates
    constexpr int MAXC = 64;
    HeaderCandidate cand[MAXC];
    int nc = 0;

    for (int o = 0; o + 20 <= len && nc < MAXC; o++) {
        const byte *p = buf + o;
        const int md = magic_hamming4(p);
        const int ver = p[4];
        const int format = p[5];
        const int method = p[6];

        // cheap prefilter: every real UPX header has a plausible version
        // byte, or the magic itself is a close fuzzy match
        if (!version_plausible(ver) && md > 2)
            continue;

        HeaderCandidate best;
        best.boff = o;
        best.magic_dist = md;

        // When the version byte is plausible the on-disk header size is fully
        // determined by version+format; evaluate that size first and avoid
        // spurious smaller-size checksum coincidences in zero padding.
        int sizes[6];
        int nsizes = 0;
        const int expected_s = expected_header_size(ver, format);
        if (version_plausible(ver)) {
            sizes[nsizes++] = expected_s;
        } else {
            for (int s : kHeaderSizes)
                sizes[nsizes++] = s;
        }

        for (int si = 0; si < nsizes; si++) {
            const int s = sizes[si];
            if (o + s > len)
                continue;
            HeaderCandidate c;
            c.boff = o;
            c.magic_dist = md;
            c.hdr_size = s;

            // one pass sum; derive every single-byte checksum solution from
            // the modular residual (keeps scanning O(len * header_sizes))
            unsigned sum_fields = 0;
            for (int i = 4; i < s - 1; i++)
                sum_fields += p[i];
            const byte stored_cksum = p[s - 1];
            c.checksum_ok = ((sum_fields % 251) == stored_cksum);
            c.format_valid = Packer::isValidFormat(format);
            c.version_plausible = version_plausible(ver);
            c.method_plausible = method_plausible(method);
            c.lengths_sane = lengths_sane_le(p, format, s, len - o);

            // check whether the checksum equation can reconstruct one of the
            // structural bytes (version/format/method) to a valid value
            for (int pos = 4; pos <= 6 && c.single_byte_pos < 0; pos++) {
                const unsigned others = sum_fields - p[pos];
                unsigned r = (stored_cksum + 251u - (others % 251)) % 251;
                int candidates_v[2] = {(int) r, (int) (r + 251 <= 255 ? r + 251 : -1)};
                for (int v : candidates_v) {
                    if (v < 0)
                        continue;
                    bool ok_semantic = true;
                    if (pos == 4)
                        ok_semantic = version_plausible(v);
                    else if (pos == 5)
                        ok_semantic = Packer::isValidFormat(v);
                    else if (pos == 6)
                        ok_semantic = method_plausible(v);
                    if (ok_semantic) {
                        c.single_byte_pos = pos;
                        c.single_byte_value = v;
                        break;
                    }
                }
            }

            int score = 0;
            if (c.checksum_ok)
                score += 60;
            score += 40 - md * 10; // exact magic 40, distant magic ~0
            if (c.format_valid)
                score += 30;
            if (c.version_plausible)
                score += 20;
            if (c.method_plausible)
                score += 15;
            if (c.lengths_sane)
                score += 10;
            if (c.single_byte_pos >= 0)
                score += 25;
            c.score = score;

            if (c.score > best.score)
                best = c;
        }

        // Strict acceptance gate: zero-filled / random offsets must not flood
        // the candidate list. Require a coherent structural header, a
        // checksum-guided structural solve, or a close fuzzy magic anchor.
        bool coherent = best.version_plausible && best.format_valid && best.method_plausible;
        bool structural_solve = best.single_byte_pos >= 0;
        bool fuzzy_anchor = md <= 2 && (best.format_valid || best.version_plausible);
        bool accept = (coherent && (best.checksum_ok || structural_solve || best.lengths_sane ||
                                    md <= 3)) ||
                      structural_solve || fuzzy_anchor;
        if (accept)
            cand[nc++] = best;
    }

    // insertion sort by score (descending)
    for (int i = 1; i < nc; i++) {
        HeaderCandidate key = cand[i];
        int j = i - 1;
        while (j >= 0 && cand[j].score < key.score) {
            cand[j + 1] = cand[j];
            j--;
        }
        cand[j + 1] = key;
    }

    int n = nc < max_out ? nc : max_out;
    for (int i = 0; i < n; i++)
        out[i] = cand[i];
    return n;
}

/*************************************************************************
// PE helper for the standalone diagnosis report
**************************************************************************/

struct PeInfo {
    bool is_pe = false;
    bool is_pe32p = false;
    unsigned pe_off = 0;
    unsigned nsec = 0;
    unsigned opt_size = 0;
    unsigned sec_table = 0;
    struct Sec {
        char name[9];
        unsigned vsize, vaddr, rsize, rptr;
    };
    Sec secs[16];
};

static bool parse_pe(const byte *d, long n, PeInfo &pe) noexcept {
    if (n < 0x40 || d[0] != 'M' || d[1] != 'Z')
        return false;
    unsigned pe_off = get_le32(d + 0x3c);
    if (pe_off + 24 > (unsigned) n)
        return false;
    if (d[pe_off] != 'P' || d[pe_off + 1] != 'E' || d[pe_off + 2] != 0 || d[pe_off + 3] != 0)
        return false;
    pe.is_pe = true;
    pe.pe_off = pe_off;
    pe.nsec = get_le16(d + pe_off + 6);
    pe.opt_size = get_le16(d + pe_off + 20);
    unsigned magic = get_le16(d + pe_off + 24);
    pe.is_pe32p = (magic == 0x20b);
    pe.sec_table = pe_off + 24 + pe.opt_size;
    if (pe.nsec > 16 || pe.sec_table + 40u * pe.nsec > (unsigned) n)
        return true; // report header even if sections unreadable
    for (unsigned i = 0; i < pe.nsec; i++) {
        const byte *s = d + pe.sec_table + 40 * i;
        memset(pe.secs[i].name, 0, sizeof(pe.secs[i].name));
        for (int j = 0; j < 8; j++) {
            char ch = (char) s[j];
            pe.secs[i].name[j] = (ch >= 32 && ch < 127) ? ch : '.';
        }
        pe.secs[i].vsize = get_le32(s + 8);
        pe.secs[i].vaddr = get_le32(s + 12);
        pe.secs[i].rsize = get_le32(s + 16);
        pe.secs[i].rptr = get_le32(s + 20);
    }
    return true;
}

static const char *format_name(int format) {
    switch (format) {
    case UPX_F_DOS_COM: return "dos/com";
    case UPX_F_DOS_SYS: return "dos/sys";
    case UPX_F_DOS_EXE: return "dos/exe";
    case UPX_F_W32PE_I386: return "win32/pe-i386";
    case UPX_F_W64PE_AMD64: return "win64/pe-amd64";
    case UPX_F_LINUX_ELF_i386: return "linux/elf32-i386";
    case UPX_F_LINUX_ELF64_AMD64: return "linux/elf64-amd64";
    case UPX_F_MACH_AMD64: return "macho/amd64";
    case UPX_F_MACH_ARM64: return "macho/arm64";
    default: return "unknown/other";
    }
}

/*************************************************************************
// standalone diagnose
**************************************************************************/

int diagnose_path(const char *path) noexcept {
    fprintf(stdout, "UPX deformation diagnosis for: %s\n", path);

    FILE *f = fopen(path, "rb");
    if (!f) {
        printErr(path, "cannot open file: %s", strerror(errno));
        return 4;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        printErr(path, "cannot seek file: %s", strerror(errno));
        return 4;
    }
    long fsize = ftell(f);
    rewind(f);
    if (fsize <= 0) {
        fclose(f);
        printErr(path, "empty or invalid file size");
        return 4;
    }
    constexpr long MAX_READ = 256L * 1024 * 1024;
    long read_size = fsize < MAX_READ ? fsize : MAX_READ;
    byte *data = (byte *) malloc((size_t) read_size + 64);
    if (!data) {
        fclose(f);
        printErr(path, "out of memory reading %ld bytes", read_size);
        return 4;
    }
    size_t rd = fread(data, 1, (size_t) read_size, f);
    fclose(f);
    long n = (long) rd;

    fprintf(stdout, "  file size      : %ld bytes%s\n", fsize,
            fsize > MAX_READ ? " (scan capped at 256 MiB)" : "");

    PeInfo pe;
    if (parse_pe(data, n, pe)) {
        fprintf(stdout, "  executable type: PE %s (%u sections)\n", pe.is_pe32p ? "PE32+" : "PE32",
                pe.nsec);
        for (unsigned i = 0; i < pe.nsec && i < 16; i++) {
            fprintf(stdout, "    section[%u] name='%s' vaddr=%#08x rawptr=%#08x rawsize=%#x\n", i,
                    pe.secs[i].name, pe.secs[i].vaddr, pe.secs[i].rptr, pe.secs[i].rsize);
        }
        bool upx_named = false;
        for (unsigned i = 0; i < pe.nsec && i < 16; i++)
            if (memcmp(pe.secs[i].name, "UPX", 3) == 0)
                upx_named = true;
        if (!upx_named)
            fprintf(stdout,
                    "  note           : no section name starts with 'UPX' (renamed/wiped?)\n");
    } else if (n >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' &&
               data[3] == 'F') {
        fprintf(stdout, "  executable type: ELF\n");
    } else {
        fprintf(stdout, "  executable type: unrecognized (no MZ/PE or ELF lead)\n");
    }

    // exact magic occurrences
    int exact_count = 0;
    for (long i = 0; i + 4 <= n; i++)
        if (get_le32(data + i) == UPX_MAGIC_LE32)
            exact_count++;
    fprintf(stdout, "  exact 'UPX!' headers found: %d\n", exact_count);

    constexpr int MAXC = 24;
    HeaderCandidate cands[MAXC];
    int nc = find_header_candidates(data, (int) (n > INT_MAX ? INT_MAX : n), cands, MAXC);
    fprintf(stdout, "  structural/fuzzy candidates : %d\n", nc);

    if (nc == 0) {
        fprintf(stdout,
                "  VERDICT: no UPX pack-header candidate survived structural checks.\n"
                "           Specific reason: magic is absent/damaged beyond fuzzy matching AND\n"
                "           no offset has a valid/checksum-repairable version/format/length set.\n"
                "           This is not a recoverable deformed UPX shell with this build.\n");
        free(data);
        return 2;
    }

    int rc = 0;
    // Confidence gating: random files contain checksum-valid-looking 32 byte
    // windows by chance. A high top score or an exact PE section-layout match
    // is required to call the file a deformed UPX shell.
    bool pe_layout_match = false;
    if (nc > 0 && pe.is_pe) {
        const HeaderCandidate &z = cands[0];
        for (unsigned i = 0; i < pe.nsec && i < 16; i++) {
            unsigned rptr = pe.secs[i].rptr;
            if (rptr == 0)
                continue;
            if ((unsigned) z.boff + z.hdr_size == rptr ||
                ((unsigned) z.boff < rptr && rptr - (unsigned) z.boff <= 128))
                pe_layout_match = true;
            if (memcmp(pe.secs[i].name, "UPX", 3) == 0)
                pe_layout_match = true;
        }
    }
    bool confident = nc > 0 && (cands[0].score >= 150 || pe_layout_match);

    for (int ci = 0; ci < nc && ci < 5; ci++) {
        const HeaderCandidate &c = cands[ci];
        const byte *p = data + c.boff;
        const int s = c.hdr_size;
        fprintf(stdout, "\n  candidate #%d at file offset %#x (score=%d, header_size=%d)\n", ci + 1,
                (unsigned) c.boff, c.score, s);
        fprintf(stdout, "    magic bytes   : %02x %02x %02x %02x ('%c%c%c%c'), hamming-distance=%d\n",
                p[0], p[1], p[2], p[3], (p[0] >= 32 && p[0] < 127) ? p[0] : '.',
                (p[1] >= 32 && p[1] < 127) ? p[1] : '.', (p[2] >= 32 && p[2] < 127) ? p[2] : '.',
                (p[3] >= 32 && p[3] < 127) ? p[3] : '.', c.magic_dist);
        int format = p[5];
        fprintf(stdout,
                "    version=%d format=%d (%s) method=%d level=%d\n", p[4], format,
                format_name(format), p[6], p[7] & 15);
        if (format < 128 && format != UPX_F_DOS_COM && format != UPX_F_DOS_SYS &&
            format != UPX_F_DOS_EXE && format != UPX_F_DOS_EXEH) {
            fprintf(stdout, "    u_len=%u c_len=%u u_file_size=%u\n", get_le32(p + 16),
                    get_le32(p + 20), get_le32(p + 24));
        }
        upx_uint8_t calc = packheader_checksum(p, s);
        fprintf(stdout, "    hdr checksum  : stored=%#04x computed=%#04x -> %s\n", p[s - 1], calc,
                c.checksum_ok ? "VALID" : "MISMATCH");

        if (c.magic_dist > 0)
            fprintf(stdout, "    repair action : restore magic constant to 'UPX!'\n");
        if (!c.checksum_ok) {
            fprintf(stdout, "    repair action : recompute header checksum byte to %#04x\n", calc);
            if (c.single_byte_pos >= 0) {
                const char *fname = "?";
                switch (c.single_byte_pos) {
                case 4: fname = "version"; break;
                case 5: fname = "format"; break;
                case 6: fname = "method"; break;
                case 7: fname = "level"; break;
                case 8 ... 11: fname = "u_adler"; break;
                case 12 ... 15: fname = "c_adler"; break;
                case 16 ... 19: fname = "u_len"; break;
                case 20 ... 23: fname = "c_len"; break;
                case 24 ... 27: fname = "u_file_size"; break;
                default: fname = "header-field"; break;
                }
                fprintf(stdout,
                        "    repair option : checksum equation reconstructs header byte[%d] (%s)"
                        " as %d (original stored checksum stays authentic)\n",
                        c.single_byte_pos, fname, c.single_byte_value);
            }
        }

        // Payload Adler / bounds assessment is only meaningful for the best
        // ranked candidate; weaker candidates are printed for transparency but
        // must not decide the verdict.
        if (ci == 0 && s == 32 && format < 128 && c.lengths_sane) {
            unsigned c_len = get_le32(p + 20);
            unsigned c_adler = get_le32(p + 12);
            unsigned payload_off = (unsigned) c.boff + 32;
            if ((upx_uint64_t) payload_off + c_len <= (upx_uint64_t) n) {
                unsigned actual = upx_adler32(data + payload_off, c_len, 1);
                fprintf(stdout,
                        "    payload c_adler: header=%08x actual=%08x -> %s (at file offset %#x)\n",
                        c_adler, actual, actual == c_adler ? "MATCH" : "MISMATCH", payload_off);
                if (actual != c_adler && c.checksum_ok && c.magic_dist == 0 && confident) {
                    fprintf(stdout,
                            "    SPECIFIC FAILURE: authentic header checksum proves c_adler field"
                            " is original; mismatch means the compressed stream (%u bytes at %#x)"
                            " is corrupted/truncated, not merely the header.\n",
                            c_len, payload_off);
                    rc = 3;
                } else if (actual != c_adler) {
                    fprintf(stdout,
                            "    note: c_adler mismatch is inconclusive because the header itself"
                            " needs repair; 'upx -d' retries without the checksum gate.\n");
                }
            } else {
                fprintf(stdout,
                        "    SPECIFIC FAILURE: c_len=%u exceeds readable file bytes from payload"
                        " offset %#x (file truncated or length field corrupted).\n",
                        c_len, payload_off);
                if (confident)
                    rc = 3;
            }
        }
    }

    if (!confident) {
        fprintf(stdout,
                "\n  VERDICT: only weak/random header candidates found (top score %d); no strong"
                " magic, checksum or PE-layout evidence. Probably not a deformed UPX shell.\n",
                nc > 0 ? cands[0].score : 0);
        free(data);
        return 2;
    }

    if (rc == 0)
        fprintf(stdout, "\n  VERDICT: UPX shell recognized; header damage is repairable. Run"
                        " 'upx -d -f <file>' (repair is enabled by default).\n");
    else
        fprintf(stdout, "\n  VERDICT: UPX shell detected but a specific unrecoverable condition was"
                        " found; see SPECIFIC FAILURE above.\n");
    free(data);
    return rc;
}

} // namespace upx_repair
