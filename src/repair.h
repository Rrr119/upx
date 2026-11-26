/* repair.h -- tolerant recognition and repair of deformed UPX shells

   This file is part of the UPX executable compressor.

   Extensions added for deformed-shell recovery:
     - diagnostic trail with specific, actionable failure reasons
     - fuzzy "UPX!" magic matching
     - checksum-guided reconstruction of a single corrupted header byte
     - candidate header scanning used by the format frontends

   The primitives are intentionally standalone so they can be exercised by
   the pack header decoder, the PE frontend and the "--diagnose" command.
 */

#pragma once

#include "conf.h"

/*************************************************************************
// per-file diagnostic trail
**************************************************************************/

namespace upx_repair {

constexpr unsigned NO_OFFSET = 0xffffffffu;

enum DiagLevel {
    DIAG_INFO = 0,      // candidate tracing, only shown by --diagnose/-vv
    DIAG_REPAIRED = 1,  // a concrete repair was successfully applied
    DIAG_WARN = 2,      // recovered, but integrity could not be fully proven
    DIAG_FAIL = 3,      // decisive reason why unpacking is impossible/unsafe
};

struct DiagEntry {
    int level = DIAG_INFO;
    unsigned offset = NO_OFFSET; // absolute file offset, when known
    char code[40] = {};           // stable machine readable reason code
    char message[360] = {};       // specific human readable explanation
};

class DiagLog final {
public:
    void clear() noexcept;
    void add(int level, unsigned offset, const char *code, const char *fmt, ...)
        noexcept attribute_format(5, 6);
    int size() const noexcept { return count; }
    const DiagEntry &at(int i) const noexcept { return entries[i]; }

private:
    static constexpr int MAX_ENTRIES = 96;
    DiagEntry entries[MAX_ENTRIES];
    int count = 0;
};

// Unique per-process trail; do not share across files.
DiagLog &diag() noexcept;

void reset_for_file(const char *name) noexcept;
const char *current_name() noexcept;

// Print REPAIRED/WARN notes after a successful recovery.
void emit_repair_notes(const char *iname) noexcept;

// Print the specific failure trail after an unpack/test/list error.
// When suppress_weak is true (generic "not packed by UPX" outcome), only
// decisive FAIL entries are printed, avoiding misleading recovery noise on
// ordinary non-UPX executables.
void emit_failure_trail(const char *iname, bool suppress_weak = false) noexcept;

/*************************************************************************
// pack header primitives (same on-disk layout as PackHeader)
**************************************************************************/

// "UPX!" magic as little endian 32 bit value.
constexpr upx_uint32_t UPX_MAGIC = 0x21585055u;

// Additive header checksum: sum(p[4 .. hdr_size-2]) % 251.
upx_uint8_t packheader_checksum(const byte *p, int hdr_size) noexcept;

// Hamming distance of p[0..3] to "UPX!"; needs 4 readable bytes.
int magic_hamming4(const byte *p) noexcept;

// Return true if p[0..3] is within max_dist byte differences of "UPX!".
bool magic_looks_like_upx(const byte *p, int max_dist) noexcept;

// Solve the checksum equation for one replaced header byte.
//
// Returns the number (0..max_values) of byte values v in [0,255] for which
//   packheader_checksum() == p[hdr_size-1] after setting p[pos] = v.
// pos must be in [4, hdr_size-2].
int solve_single_byte_values(const byte *p, int hdr_size, int pos, int *values,
                             int max_values) noexcept;

// Header sizes used by UPX across versions/formats, descending preference.
extern const int kHeaderSizes[6];

/*************************************************************************
// fuzzy candidate scanning
**************************************************************************/

struct HeaderCandidate {
    int boff = -1;            // offset within scanned buffer
    int magic_dist = 4;       // Hamming distance to "UPX!" (0 == exact)
    int hdr_size = 0;         // best matching on-disk header size
    int score = 0;
    bool checksum_ok = false; // original stored header checksum validates
    bool format_valid = false;
    bool version_plausible = false;
    bool method_plausible = false;
    bool lengths_sane = false;
    int single_byte_pos = -1; // checksum-guided repair position, -1 if none
    int single_byte_value = -1;
};

// Scan buf[0..len) for plausible UPX pack headers, ranked by score.
// Returns number of candidates written to out (highest scores first).
int find_header_candidates(const byte *buf, int len, HeaderCandidate *out, int max_out) noexcept;

/*************************************************************************
// standalone "--diagnose" implementation
//
// Reads path, locates UPX headers with all recovery strategies and prints a
// specific report.  Returns:
//   0  an intact or fully repairable UPX header was found
//   2  no UPX signature/candidate found at all
//   3  UPX header found but damage is not repairable
//   4  file cannot be read / not a usable executable
**************************************************************************/

int diagnose_path(const char *path) noexcept;

} // namespace upx_repair
