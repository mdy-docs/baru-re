#ifndef REGEXP_H
#define REGEXP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 32768, not the original 16384: string-set classes compile to one
 * alternation branch per string (see re_compiler.c), and a full
 * \p{RGI_Emoji} -- 2604 sequences now that CharClass.strings is heap-sized
 * rather than capped at 128 -- needs ~17.5k instructions on its own. */
#define MAX_OPCODES 32768
#define MAX_GROUPS 255
/* 256, not the original 64: real-world patterns clear 64 (test262's
 * classic XML shallow-parsing regex builds 72 distinct classes in one
 * pattern). Only a cap on the id space: the slot table is on the heap and
 * grows with the classes a pattern actually has (Program.classes). */
#define MAX_CLASSES 256
/* 256, not the original 16: every quantifier consumes a counter id, and
 * ordinary real-world patterns blow past 16 -- test262's classic XML
 * shallow-parsing regex (a single 907-char pattern) needs 75. Cheap to
 * raise now that the VM sizes ALL counter storage (per-thread arenas,
 * fail-cache side arrays, path-start snapshots) to the pattern's actual
 * counter_count on the heap -- this constant only caps the compile-time
 * id space. */
#define MAX_COUNTERS 256
#define CACHE_SIZE 8192
/* Capture-group name buffer size in bytes: 31 UTF-8 bytes + NUL. An engine
 * limit, not a spec one (ECMAScript puts no length cap on group names) --
 * over-long names fail compilation loudly.
 * Shared by Program.group_names' entries, the parser/lexer's Token/ASTNode name
 * buffers, and the append bound in rx_name_append_utf8; sizing one without
 * the others would silently reintroduce a truncation bug. */
#define MAX_GROUP_NAME 32

/* Unlike the four MAX_* above (which cap id spaces and are checked at
 * their respective allocation sites), this
 * bounds AST *height*, not a data structure's capacity: the parser
 * (re_parser.c) computes each node's subtree height as it's built and
 * rejects a pattern before its AST would grow deep enough to overflow the
 * C stack in one of the several functions that recurse through it with no
 * depth limit of their own (free_ast, validate_group_names,
 * validate_backrefs, validate_named_backrefs, compile_node).
 * Two changes made 400 safe where 200 once was the ceiling:
 * validate_group_names' two ~8KB NameSet locals per frame (ASan-observed
 * crash near depth ~247 on an 8MB stack) are gone (it now works on one
 * caller-owned stack of name pointers), and the
 * parser now builds BALANCED concat/alternation trees, so height tracks
 * real bracket nesting rather than pattern length. The remaining
 * recursions carry small frames -- the largest per-level cost is vm_run's
 * lookaround recursion (a cap_pairs-sized VLA, ~4KB worst case), which at
 * 400 levels stays ~1.6MB against the 8MB native and WASM (Makefile
 * STACK_SIZE) stacks. test262's classic suites nest 200 parens; 400
 * accommodates that with the same 2x headroom the old value had over
 * hand-written patterns. */
#define MAX_AST_DEPTH 400

#define REGEX_FLAG_IGNORECASE 1
#define REGEX_FLAG_GLOBAL 2
#define REGEX_FLAG_MULTILINE 4
#define REGEX_FLAG_DOTALL 8
#define REGEX_FLAG_STICKY 16
#define REGEX_FLAG_UNICODE 32
#define REGEX_FLAG_INDICES 64
#define REGEX_FLAG_UNICODE_SETS 128

/* ---- Injectable allocator ------------------------------------------------
 *
 * Every byte this engine allocates -- compiled bytecode, parser AST nodes,
 * character-class range/string buffers, the per-match VMContext and its
 * per-depth thread arenas -- goes through one of these, so an embedder that
 * meters or caps its own heap can meter and cap the regex engine too. A host
 * that supplies none gets plain libc malloc/realloc/free, which is what the
 * standalone library, its smoke suite and its fuzzer all run on.
 *
 * The handle is carried per-Program (program_set_allocator) and per-VMContext
 * (inherited from the Program it is created for), never in a global: a host
 * with several independent heaps -- one per sandboxed guest, say -- must be
 * able to charge each pattern to the heap that owns it, and a process-wide
 * hook would misattribute the moment two of them are live at once.
 *
 * One realloc-shaped entry point covers all three operations:
 *   ptr == NULL     -> allocate new_size bytes (never called with 0)
 *   new_size == 0   -> free ptr, return NULL
 *   otherwise       -> resize ptr to new_size, NULL on failure (ptr survives)
 * The OLD size is deliberately not passed: no call site in this engine tracks
 * one for its malloc-shaped allocations, so an allocator that needs the old
 * size (to maintain a live-byte total by delta, say) must record it itself --
 * a size header in front of each block is the usual way.
 *
 * A NULL return is never fatal here: compile-time failures surface through
 * Program.error and match-time ones through vm_context_budget_exhausted (see
 * both below). The allocator must not longjmp or exit. */
typedef void* (*RegexReallocFn)(void* userdata, void* ptr, size_t new_size);

typedef struct {
    RegexReallocFn fn; /* NULL = libc malloc/realloc/free */
    void* ud;
} RegexAllocator;

/* The enum members ARE the short names: every use site already said OP_*
 * (via a full set of aliasing macros this header used to carry); the
 * REGEX_OP_* spellings were referenced nowhere else in this repo or by
 * any known consumer, so the double naming was collapsed. */
typedef enum {
    OP_CHAR, OP_CLASS, OP_SPLIT, OP_JMP, OP_SAVE, OP_LOOKAHEAD, OP_NEG_LOOKAHEAD, OP_MATCH,
    OP_INIT_COUNTER, OP_INC_COUNTER, OP_CHECK_COUNTER, OP_ASSERT_START, OP_ASSERT_END, OP_BACKREF, OP_NAMED_BACKREF, OP_WORD_BOUNDARY,
    OP_NON_WORD_BOUNDARY, OP_LOOKBEHIND, OP_NEG_LOOKBEHIND, OP_CLEAR_CAPTURES
} RegexOpCode;

typedef struct {
    RegexOpCode op;
    int arg1;
    int arg2;
    int arg3;  // Max bounds for OP_CHECK_COUNTER
    int arg4;  // Jump target for OP_CHECK_COUNTER
    bool lazy; // Lazy routing flag
} Instruction;

typedef struct {
    uint32_t start;
    uint32_t end;
} CodePointRange;

typedef struct {
    uint32_t cps[16]; // Max length of a string in a class (e.g. complex emojis)
    int length;
} StringSequence;

/* Both buffers are heap-owned and right-sized (grown on demand; NULL iff
 * the corresponding count is 0). ranges was a fixed [2048] embedded array
 * (~16KB per class, the dominant term in Program's old multi-MB footprint)
 * and strings a fixed [128] one (which silently truncated the large
 * Unicode properties of strings -- RGI_Emoji alone has 2604 sequences).
 * Ownership: a CharClass owns its buffers; copies must deep-copy
 * (re_lexer.c's class_strings_push / add_range) or deliberately transfer
 * ownership through a struct assignment AFTER freeing the destination's
 * own buffers (class_free), which is also how compile_into re-entry and
 * program_release tear classes down. A Program must be ZERO-INITIALIZED
 * before its first compile_into so those frees never see garbage
 * pointers. */
typedef struct {
    CodePointRange* ranges;
    int range_count;
    int range_cap;
    StringSequence* strings;
    int string_count;
    int string_cap;
    bool negated;
    /* Which allocator owns the two buffers above (NULL = libc). A class is
     * reached through neither a Program nor a Lexer at most of its ~140
     * construction and teardown sites -- set-algebra temporaries, builtin
     * fills, the \p{...} cache -- so the handle rides on the class itself
     * rather than being threaded through all of them. It must be set before
     * the first buffer is allocated and must not change while any is live:
     * every grow and every free reads it back from here, so a class whose
     * handle changed mid-life would be freed by an allocator other than the
     * one that produced its memory. Copies made by the ownership-transfer
     * idiom carry it along like the pointers it describes. */
    const RegexAllocator* alloc;
} CharClass;

/* code is heap-owned and right-sized: emit() (re_compiler.c) grows it on
 * demand up to the MAX_OPCODES hard cap, and compile_into re-entry reuses
 * the buffer across recompiles. It was a fixed Instruction[MAX_OPCODES]
 * embedded array -- 786KB per Program whether the pattern needed 10
 * instructions or 30k.
 *
 * The class slots and the group names are on the heap for the same reason:
 * as embedded MAX_CLASSES/MAX_GROUPS-sized arrays they were ~21KB in every
 * Program, which is what a host holding (or merely constructing) many small
 * patterns paid for each one -- /a+b/ has no class and no name. The struct
 * is now a ~150-byte header, and a compiled pattern costs what it uses. */
typedef struct {
    Instruction* code;
    int code_cap;
    /* class_cap slots, class_count in use; grown by the lexer as classes
     * appear (so a pointer to a slot does not survive the next class being
     * allocated), kept across recompiles like code. NULL iff class_cap is 0. */
    CharClass* classes;
    int class_cap;
    /* The names of groups 0..name_cap-1 (an unnamed group's is ""), or NULL
     * with name_cap 0 when the pattern names no group. It ends at the last
     * named group, not at group_count, so read it through
     * program_group_name. */
    char (*group_names)[MAX_GROUP_NAME];
    int name_cap;
    /* name_chain[i] = the next group id > i sharing group i's name (0 =
     * none), for i < name_cap; NULL like group_names. Built once by
     * compile_into after parsing; OP_NAMED_BACKREF
     * walks it to find the participating group among ES2025 duplicate
     * names, replacing the strcmp scan over every group name the VM used
     * to do per execution. */
    int* name_chain;
    /* How deeply the pattern nests lookarounds (0 = it has none). Each
     * level is one recursive VM entry with its own scratch, so this is what
     * sizes a VMContext. */
    int look_depth;
    int code_count;
    int class_count;
    int group_count;
    int counter_count;
    bool ignore_case;
    bool multiline;
    bool dot_all;
    bool sticky;
    bool unicode;
    bool has_indices;
    bool unicode_sets;
    /* Set by the compiler when any (numeric or named) backreference is
     * emitted. The VM's fail cache keys on (pc, sp, counters) but NOT on
     * capture state, and captures feed back into matching only through
     * backreferences -- so memoizing failures is unsound exactly when this
     * is set (a cached failure from one capture history wrongly suppressed
     * a viable thread with another: /(?:(x)|x)*\1y/ vs "xy"). The VM skips
     * the cache for such patterns; the step budget remains their defense
     * against catastrophic backtracking. */
    bool has_backrefs;
    /* First-unit scan filter, computed by compile_into from the finished
     * bytecode. When scan_filter is true, a match can only START at a
     * position whose first UTF-16 code unit is admitted: units < 128 are
     * looked up in the scan_ascii bitmap, units >= 128 (including all
     * surrogates) are admitted iff scan_non_ascii. An unanchored scan loop
     * can skip inadmissible positions without entering the VM at all --
     * regex_wasm.c's regex_exec does exactly this; native scan loops may
     * too. The filter OVER-approximates (skipping is only ever safe, never
     * required); it is left false whenever a conservative answer isn't
     * cheap -- patterns that can match empty, or whose first consuming
     * opcode is a backreference or lookaround. */
    bool scan_filter;
    bool scan_non_ascii;
    uint8_t scan_ascii[16];
    const char* error;
    /* Allocator for everything this Program owns, and the one a VMContext
     * created for it inherits. Zero (libc) unless program_set_allocator was
     * called; compile_into and program_release both preserve it, so it
     * survives recompiles and outlives every buffer it produced. */
    RegexAllocator alloc;
} Program;

typedef struct {
    int start;
    int end;
} CaptureIndex;

void compile_into(Program* prog, const uint16_t* regex, int flags);

/* The name of capture group `group` (1-based), "" when it has none or is out
 * of range. The way to read Program.group_names: the table exists only for a
 * pattern that names a group, and stops at the last one that does. */
static inline const char* program_group_name(const Program* prog, int group) {
    return group >= 0 && group < prog->name_cap ? prog->group_names[group] : "";
}

/* Routes every allocation this Program (and any VMContext created for it)
 * makes through fn/userdata instead of libc. Call on a ZERO-INITIALIZED
 * Program before its first compile_into: the handle is read back at every
 * grow and every free, so switching it while buffers are live would free
 * that memory through the wrong allocator. Passing fn == NULL restores the
 * libc default. */
void program_set_allocator(Program* prog, RegexReallocFn fn, void* userdata);

/* Releases one class's heap-owned buffers, ranges and strings both (safe
 * on an empty class; the pointers are NULLed). */
void class_free(CharClass* cls);

/* Releases every heap buffer a Program owns -- the code array, the class
 * slots and all classes' range/string buffers, the group names -- leaving
 * the struct reusable for another
 * compile_into (and safe to call on a zero-initialized, never-compiled
 * Program). A host that drives compile_into directly must call this before
 * discarding a Program; the regex_wasm.c shim's regex_free does. */
void program_release(Program* prog);

/* Reusable execution scratch (backtrack stacks, capture arenas, fail
 * caches -- one set per lookaround recursion depth the pattern can reach,
 * each allocated at first use, grown as a match needs and
 * kept until freed; a context that has matched a simple pattern holds a few
 * hundred bytes). Create one per exec *call* and pass it to vm_execute
 * for every start position tried within that call: an unanchored search
 * over N code units re-enters the VM up to N times, and paying
 * allocation + fail-cache initialization per position instead of per call
 * dominated the runtime by orders of magnitude. A context is tied to the Program it was
 * created for as that Program was compiled (its group count, its lookaround
 * depth): recompile the Program and the context must be replaced. It is not
 * thread-safe -- one context per thread. */
typedef struct VMContext VMContext;
/* NULL if the context could not be allocated. A caller that treats that as
 * "no match" reports a wrong answer; treat it like budget exhaustion below
 * -- the match could not be evaluated. The context is allocated with, and
 * itself allocates through, prog's allocator, so the pattern and the memory
 * spent matching it are charged to the same place. */
VMContext* vm_context_new(const Program* prog);
void vm_context_free(VMContext* ctx);

/* Hard step budget: the maximum number of VM instructions this context may
 * execute across every vm_execute entry (including lookaround recursion)
 * for the context's whole lifetime. 0 (the default) means unlimited --
 * existing consumers are unaffected unless they opt in. When the budget is
 * exhausted the in-flight match is abandoned (vm_execute returns false)
 * and vm_context_budget_exhausted() reports
 * true, letting a host distinguish "no match" from "gave up" and surface a
 * catchable error instead of hanging. This is the engine's defense against
 * catastrophic backtracking that the fail cache does not catch: the cache
 * is direct-mapped (at most CACHE_SIZE slots, collisions evict) and is
 * generation-cleared across lookaround boundaries, so pathological
 * patterns -- /(a+)+$/ against a few hundred 'a's is enough -- still
 * backtrack exponentially without a budget. Embedders running untrusted
 * patterns should always set one; a budget linear in the subject length
 * (e.g. 1e6 + 2000/unit) bounds superlinear blowup while leaving orders of
 * magnitude of headroom for legitimate matching.
 *
 * A match-time ALLOCATION FAILURE (the VM's backtrack stack and fail cache
 * grow on demand) abandons the in-flight match identically and reports
 * through this same flag: to a host the two are one condition -- "the
 * engine could not finish this match" -- which must surface as an error,
 * never as a non-match. Compile-time allocation failures are separate; they
 * report through Program.error like any other compile error. */
void vm_context_set_step_budget(VMContext* ctx, uint64_t max_steps);
bool vm_context_budget_exhausted(const VMContext* ctx);

/* The backtrack stack's bound. A greedy loop saves one entry per iteration, so a long enough
 * run of matching text needs a deep stack; a context's stacks (one per lookaround depth) may
 * come to max_bytes together, 64MB unless set here, which is V8's figure for its own. A match
 * that needs more is abandoned as an exhausted budget abandons it -- vm_execute returns false
 * and vm_context_budget_exhausted reports true, because "no match" would be a wrong answer --
 * and vm_context_stack_exhausted tells the two apart (V8 throws a RangeError here). The state
 * is sticky like the budget's and cleared by re-arming it (vm_context_set_step_budget, with 0
 * for a host that sets none); the context stays usable. A depth's first few entries are given
 * whatever the limit, which bounds growth. vm_context_stack_bytes is what the stacks hold now:
 * they are kept for the context's lifetime, so a host that keeps contexts can free one that a
 * single deep match left large. */
void vm_context_set_stack_limit(VMContext* ctx, size_t max_bytes);
size_t vm_context_stack_bytes(const VMContext* ctx);
bool vm_context_stack_exhausted(const VMContext* ctx);

/* The steps the context has spent since its budget was last armed (with no budget, none are
 * counted: 0). A host that bills the engine's work to a budget of its own -- an instruction
 * budget in a script engine, say -- arms the step budget to what it can afford, then charges
 * what was actually spent. */
uint64_t vm_context_steps_used(const VMContext* ctx);

/* An interrupt flag the VM polls while it runs: every 4096 steps, and only under a step budget
 * (the flag is read where the steps are counted). Once it reads nonzero the in-flight match is
 * abandoned as an exhausted budget abandons it -- vm_execute returns false and
 * vm_context_budget_exhausted reports true -- and vm_context_interrupted tells the two apart.
 * The flag is the host's: set from another thread or a signal handler, it stops a long match
 * without waiting for the budget. NULL (the default) polls nothing. Re-arming the budget clears
 * the interrupted state, not the flag. */
void vm_context_set_interrupt(VMContext* ctx, const volatile int* flag);
bool vm_context_interrupted(const VMContext* ctx);
bool vm_execute(Program* prog, VMContext* ctx, int start_pc, int step, const uint16_t* original_text, const uint16_t* text_end, const uint16_t* search_start, const uint16_t** out_captures);

/* One-shot convenience wrapper: creates a context, runs vm_execute once,
 * frees the context. Fine for a single anchored evaluation; do NOT call
 * this per start position in a scan loop -- that's the exact per-position
 * overhead VMContext exists to remove. */
bool vm_execute_internal(Program* prog, int start_pc, int step, const uint16_t* original_text, const uint16_t* text_end, const uint16_t* search_start, const uint16_t** out_captures);
void vm_get_indices(const uint16_t* original_text, const uint16_t** captures, CaptureIndex* out_indices, int group_count);

#endif /* REGEXP_H */
