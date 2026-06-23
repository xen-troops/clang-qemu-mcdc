/*
 * Trace conditional branch instructions evaluating condition results
 *
 * The plugin will record cpsr register or corresponding condition result
 * for each executed Aarch64 conditional instructions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

#ifndef QEMU_PACKED
#define QEMU_PACKED __attribute__((packed))
#endif

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define UUID_SIZE 36
#define NO_REG_WATCH 255

#define BC_OPCODE      0x54000000
#define BC_OPCODE_MASK 0xFF000000

#define CB_OPCODE_MASK 0x7E000000
#define CB_OPCODE      0x34000000
#define TB_OPCODE      0x36000000

#define CSEL_OPCODE_MASK 0x7FE00000
#define CSEL_OPCODE      0x1A800000

/* 5-bit register index from an AArch64 instruction */
#define RD(insn) ((insn) & 0x1F)            /* Bits [4:0]   */
#define RN(insn) (((insn) >> 5) & 0x1F)     /* Bits [9:5]   */
#define RM(insn) (((insn) >> 16) & 0x1F)    /* Bits [20:16] */

#define MAX_CONF_LINE_LENGHT 1024

typedef enum {
    BR_COND,
    BR_CBZ,
    BR_CBNZ,
    BR_TBZ,
    BR_TBNZ,
    BR_CSEL,
    BR_PSEUDO_REG_WATCH
} BranchType;

typedef struct {
    char magic[8];
    uint32_t version;
    uint64_t reserved;
    uint64_t num_cpus;
} QEMU_PACKED TraceFileHeader;

typedef struct {
    uint64_t addr;
    uint8_t cpsr_bits;
} QEMU_PACKED PendingCondEntry;

typedef struct {
    char uuid[UUID_SIZE];
    uint64_t fp;
} PendingCondKey;

typedef struct {
    char uuid[UUID_SIZE];
    uint32_t num_records;
    uint64_t exit_target;
} QEMU_PACKED CondBranchHeader;

typedef struct {
    GHashTable *running_conditions;
    GHashTable *executed_conditions;
} CpuTrace;

typedef struct {
    uint64_t insn_vaddr;
    char     uuid[UUID_SIZE];
    uint64_t cond_start;
    uint64_t cond_end;
    uint64_t target_addr;
    uint8_t  cond_code;
    BranchType branch_type;
    uint8_t  reg_idx;
    uint8_t  bit_pos;
    bool     is_64bit;
    bool     is_decoded;
} BranchExecData;

static const char *trace_file = "brtrace.dat";
static const char *config_file;

static GPtrArray *cpus_btrace;
static GHashTable *target_instructions;

static struct qemu_plugin_register *cpsr_reg;
static struct qemu_plugin_register *fp_reg;
static struct qemu_plugin_register *gp_registers[31];

static GMutex trace_lock;

/* Evaluates if a b.cond branch is taken based on N, Z, C, V flags */
static bool evaluate_arm_condition(uint8_t cond_code, uint8_t cpsr_nzcv)
{
    bool n = (cpsr_nzcv >> 3) & 1;
    bool z = (cpsr_nzcv >> 2) & 1;
    bool c = (cpsr_nzcv >> 1) & 1;
    bool v = (cpsr_nzcv >> 0) & 1;

    switch (cond_code & 0x0F) {
        case 0x0: return z == 1;              /* EQ */
        case 0x1: return z == 0;              /* NE */
        case 0x2: return c == 1;              /* CS/HS */
        case 0x3: return c == 0;              /* CC/LO */
        case 0x4: return n == 1;              /* MI */
        case 0x5: return n == 0;              /* PL */
        case 0x6: return v == 1;              /* VS */
        case 0x7: return v == 0;              /* VC */
        case 0x8: return c == 1 && z == 0;    /* HI */
        case 0x9: return c == 0 || z == 1;    /* LS */
        case 0xA: return n == v;              /* GE */
        case 0xB: return n != v;              /* LT */
        case 0xC: return z == 0 && (n == v);  /* GT */
        case 0xD: return z == 1 || (n != v);  /* LE */
        case 0xE: return true;                /* AL */
        case 0xF: return true;                /* NV */
        default:  return false;
    }
}

static void read_register(struct qemu_plugin_register *reg, void *dest,
                          size_t dest_size)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    bool success = qemu_plugin_read_register(reg, buf);

    g_assert(success);
    g_assert(buf->len > 0);

    if (buf->len == 8 && dest_size == 4) {
        uint8_t *src = buf->data;
#if G_BYTE_ORDER == G_BIG_ENDIAN
        src += 4;
#endif
        *(uint32_t *)dest = *(uint32_t *)src;
    } else {
        memcpy(dest, buf->data, buf->len);
    }
}

static void vcpu_exec_cb(unsigned int vcpu_index, void *data)
{
    uint32_t cpsr_bits;
    uint64_t fp_val;
    bool taken_exit, fallthrough_exit, is_taken = false;
    PendingCondKey lookup_key;
    BranchExecData *cbdata = data;
    GBytes *lookup_bytes;
    GArray *buffer;
    CpuTrace *cpu_trace = g_ptr_array_index(cpus_btrace, vcpu_index);

    read_register(fp_reg, &fp_val, sizeof(fp_val));

    if (cbdata->branch_type == BR_COND ||
        cbdata->branch_type == BR_CSEL) {
        uint32_t cpsr_val;
        read_register(cpsr_reg, &cpsr_val, sizeof(cpsr_val));

        cpsr_bits = (uint8_t)((cpsr_val >> 28) & 0x0F); /* NZCV */

        is_taken = evaluate_arm_condition(cbdata->cond_code, cpsr_bits);

        cpsr_bits = is_taken ? 1 : 0;
    } else if (cbdata->branch_type == BR_PSEUDO_REG_WATCH) {
        uint64_t val = 0;

        read_register(gp_registers[cbdata->reg_idx], &val,
                      cbdata->is_64bit ? 8 : 4);

        cpsr_bits = (val != 0) ? 1 : 0;
        is_taken = false;
    } else {
        uint64_t test_val = 0;

        read_register(gp_registers[cbdata->reg_idx], &test_val,
                      cbdata->is_64bit ? 8 : 4);

        if (cbdata->branch_type == BR_CBZ || cbdata->branch_type == BR_CBNZ) {
            if (cbdata->branch_type == BR_CBZ) {
                is_taken = (test_val == 0);
            } else {
                is_taken = (test_val != 0);
            }
        } else if (cbdata->branch_type == BR_TBZ ||
                   cbdata->branch_type == BR_TBNZ) {
            bool bit_val = (test_val >> cbdata->bit_pos) & 1;

            if (cbdata->branch_type == BR_TBZ) {
                is_taken = (bit_val == 0);
            } else {
                is_taken = (bit_val == 1);
            }
        }

        cpsr_bits = is_taken ? 1 : 0;
    }

    memset(&lookup_key, 0, sizeof(PendingCondKey));

    memcpy(lookup_key.uuid, cbdata->uuid, UUID_SIZE);
    lookup_key.fp = fp_val;

    lookup_bytes = g_bytes_new_static(&lookup_key, sizeof(PendingCondKey));

    buffer = g_hash_table_lookup(cpu_trace->running_conditions, lookup_bytes);
    if (!buffer) {
        PendingCondKey *new_key = g_memdup2(&lookup_key, sizeof(PendingCondKey));
        GBytes *insert_bytes = g_bytes_new_take(new_key, sizeof(PendingCondKey));

        buffer = g_array_new(FALSE, FALSE, sizeof(PendingCondEntry));
        g_hash_table_insert(cpu_trace->running_conditions, insert_bytes, buffer);
    } else if (cbdata->insn_vaddr == cbdata->cond_start) {
        /* Clear temp record if hit condition start with same frame pointer */
        g_array_set_size(buffer, 0);
    }

    PendingCondEntry record = {
        .addr = cbdata->insn_vaddr,
        .cpsr_bits = cpsr_bits
    };
    g_array_append_val(buffer, record);

    taken_exit = is_taken && (cbdata->target_addr < cbdata->cond_start ||
                                   cbdata->target_addr > cbdata->cond_end);
    fallthrough_exit = !is_taken && ((cbdata->insn_vaddr + 4) > cbdata->cond_end);

    /* On exit of condition evaluation, record it to permanent trace buffer */
    if (taken_exit || fallthrough_exit) {
        GBytes *branch_key;
        GByteArray *tmp_key;
        uint64_t *hit_count;
        uint64_t actual_exit = taken_exit ? cbdata->target_addr :
                                            (cbdata->insn_vaddr + 4);

        CondBranchHeader header = {
            .num_records = buffer->len,
            .exit_target = actual_exit
        };
        memcpy(header.uuid, cbdata->uuid, UUID_SIZE);

        tmp_key = g_byte_array_new();

        g_byte_array_append(tmp_key, (const guint8 *)&header,
                            sizeof(CondBranchHeader));
        g_byte_array_append(tmp_key, (const guint8 *)buffer->data,
                            buffer->len * sizeof(PendingCondEntry));

        branch_key = g_byte_array_free_to_bytes(tmp_key);

        hit_count = g_hash_table_lookup(cpu_trace->executed_conditions,
                                        branch_key);
        if (hit_count) {
            (*hit_count)++;
            g_bytes_unref(branch_key);
        } else {
            hit_count = g_new(uint64_t, 1);
            *hit_count = 1;
            g_hash_table_insert(cpu_trace->executed_conditions, branch_key,
                                hit_count);
        }

        g_hash_table_remove(cpu_trace->running_conditions, lookup_bytes);
    }

    g_bytes_unref(lookup_bytes);
}

static void vcpu_tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    for(int i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        uint32_t raw_opcode, opcode;
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
        int32_t offset;
        size_t data_size;

        BranchExecData *data = g_hash_table_lookup(target_instructions,
                                                   &insn_vaddr);
        if (!data) {
            continue;
        }

        if (data->is_decoded) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_exec_cb,
                                                   QEMU_PLUGIN_CB_RW_REGS, data);
            continue;
        }

        data_size = qemu_plugin_insn_data(insn, &raw_opcode, sizeof(raw_opcode));
        if (data_size < sizeof(raw_opcode)) {
            continue;
        }

        opcode = GUINT32_FROM_LE(raw_opcode);

        g_mutex_lock(&trace_lock);
        
        if ((opcode & BC_OPCODE_MASK) == BC_OPCODE) {
            data->branch_type = BR_COND;
            data->cond_code  = opcode & 0x0F;

            offset = (opcode >> 5) & 0x7FFFF; 
            if (offset & 0x40000) {
                offset |= 0xFFF80000;
            }

            data->target_addr = insn_vaddr + (offset * 4);
        } else if ((opcode & CB_OPCODE_MASK) == CB_OPCODE) {
            data->branch_type = ((opcode >> 24) & 1) ? BR_CBNZ : BR_CBZ;
            data->is_64bit   = (opcode >> 31) & 1;
            data->reg_idx    = opcode & 0x1F;

            offset = (opcode >> 5) & 0x7FFFF; 
            if (offset & 0x40000) {
                offset |= 0xFFF80000;
            }

            data->target_addr = insn_vaddr + (offset * 4);
        } else if ((opcode & CB_OPCODE_MASK) == TB_OPCODE) {
            uint8_t b5 = (opcode >> 31) & 1;
            uint8_t b40 = (opcode >> 19) & 0x1F;

            data->bit_pos = (b5 << 5) | b40;
            data->branch_type = ((opcode >> 24) & 1) ? BR_TBNZ : BR_TBZ;
            data->reg_idx    = opcode & 0x1F;

            offset = (opcode >> 5) & 0x3FFF;
            if (offset & 0x2000) {
                offset |= 0xFFFFC000;
            }

            data->target_addr = insn_vaddr + (offset * 4);
        } else if ((opcode & CSEL_OPCODE_MASK) == CSEL_OPCODE) {
            uint32_t rn = RN(opcode);
            uint32_t rm = RM(opcode);

            uint32_t op2 = (opcode >> 10) & 0x3;

            data->branch_type = BR_CSEL;
            data->cond_code  = (opcode >> 12) & 0x0F;

            /*
             * Handle aliases CSET, CINC and others:
             * 'CSET  Xd, cond' -> 'CSINC Xd, XZR, XZR, invert(cond)'
             * 'CINC  Xd, Xn, cond' -> 'CSINC Xd, Xn, Xn, invert(cond)'
             *
             * op2 == 0: CSEL  (Standard select, no inversion)
             * op2 == 1: CSINC (Aliases: CSET, CINC)
             * op2 == 2: CSINV (Aliases: CSETM, CINV)
             * op2 == 3: CSNEG (Aliases: CNEG)
             */
            bool has_alias = (op2 != 0);

            if (has_alias && rn == rm) {
                data->cond_code = data->cond_code ^ 0x1;
            }

            data->target_addr = insn_vaddr + 4;
        } else if (data->reg_idx != NO_REG_WATCH) {
            data->branch_type = BR_PSEUDO_REG_WATCH;
            data->target_addr = insn_vaddr + 4;
        } else {
            fprintf(stderr,
                    "[ERROR] Configured addr 0x%lx is not a branch and has no register attached!\n",
                    insn_vaddr);
            g_assert_not_reached();
        }

        data->is_decoded = true;
        
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_exec_cb,
                                               QEMU_PLUGIN_CB_RW_REGS, data);
        g_mutex_unlock(&trace_lock);
    }
}

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    g_mutex_lock(&trace_lock);

    if (!cpsr_reg) {
        g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
        for (int i = 0; i < reg_list->len; ++i) {
            qemu_plugin_reg_descriptor *rd = &g_array_index(reg_list,
                                                qemu_plugin_reg_descriptor, i);
            if (!strcmp(rd->name, "cpsr")) {
                cpsr_reg = rd->handle;
            } else if (!strcmp(rd->name, "x29")) {
                fp_reg = rd->handle;
            }
            
            if (rd->name[0] == 'x' && isdigit(rd->name[1])) {
                int reg_ind = atoi(&rd->name[1]);
                if (reg_ind >= 0 && reg_ind <= 30) {
                    gp_registers[reg_ind] = rd->handle;
                }
            }
        }
        g_assert(cpsr_reg);
        g_assert(fp_reg);
    }

    if (vcpu_index >= cpus_btrace->len) {
        g_ptr_array_set_size(cpus_btrace, vcpu_index + 1);
    }

    if (cpus_btrace->pdata[vcpu_index] == NULL) {
        CpuTrace *cpu_trace = g_new0(CpuTrace, 1);
        cpu_trace->running_conditions = g_hash_table_new_full(g_bytes_hash,
                                                g_bytes_equal,
                                                (GDestroyNotify)g_bytes_unref,
                                                (GDestroyNotify)g_array_unref);
        cpu_trace->executed_conditions = g_hash_table_new_full(g_bytes_hash,
                                                g_bytes_equal,
                                                (GDestroyNotify)g_bytes_unref,
                                                g_free);
        cpus_btrace->pdata[vcpu_index] = cpu_trace;
    }
    g_mutex_unlock(&trace_lock);
}

static void trace_write(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb) {
        fprintf(stderr, "ERROR: failed to write write branch trace data\n");
        exit(EXIT_FAILURE);
    }
}

static void plugin_exit_cb(qemu_plugin_id_t id, void *userdata)
{
    TraceFileHeader header = {0};
    FILE *fp = fopen(trace_file, "wb");

    if (!fp) {
        fprintf(stderr, "Failed to open trace file: %s\n", trace_file);
        return;
    }

    trace_write(&header, sizeof(TraceFileHeader), 1, fp);

    for (int vcpu_id = 0; vcpu_id < cpus_btrace->len; vcpu_id++) {
        GHashTableIter iter;
        gpointer key, value;
        CpuTrace *cpu_trace = g_ptr_array_index(cpus_btrace, vcpu_id);

        if (!cpu_trace || !cpu_trace->executed_conditions) {
            continue;
        }

        g_hash_table_iter_init(&iter, cpu_trace->executed_conditions);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            GBytes *cond_exec_bytes = (GBytes *)key;
            uint64_t hit_count = *(uint64_t *)value;

            gsize sig_size;
            gconstpointer write_data = g_bytes_get_data(cond_exec_bytes,
                                                      &sig_size);
            uint32_t write_size = (uint32_t)sig_size;

            trace_write(&hit_count, sizeof(uint64_t), 1, fp);
            trace_write(&write_size, sizeof(uint32_t), 1, fp);
            trace_write(write_data, 1, write_size, fp);
        }
        
        g_hash_table_destroy(cpu_trace->running_conditions);
        g_hash_table_destroy(cpu_trace->executed_conditions);
        g_free(cpu_trace);
    }

    fseek(fp, 0, SEEK_SET);
    memcpy(header.magic, "BRTRACE", 8);
    header.version = 1;
    header.num_cpus = cpus_btrace->len;
    trace_write(&header, sizeof(TraceFileHeader), 1, fp);

    fclose(fp);
    g_ptr_array_free(cpus_btrace, TRUE);
    g_hash_table_destroy(target_instructions);
}

static uint8_t parse_reg(const char *reg_str)
{
    if (!reg_str) {
        return NO_REG_WATCH;
    }

    if (tolower(reg_str[0]) == 'x' || tolower(reg_str[0]) == 'w') {
        int reg = atoi(&reg_str[1]);

        if (reg >= 0 && reg <= 31) {
            return (uint8_t)reg;
        }
    }

    return NO_REG_WATCH;
}

static void load_config_file(const char *filename)
{
    char line[MAX_CONF_LINE_LENGHT];

    FILE *fp = fopen(filename, "r");

    if (!fp) {
        fprintf(stderr, "Failed to open config file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    target_instructions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                                g_free, g_free);

    while (fgets(line, sizeof(line), fp)) {
        int num_tokens;
        uint64_t block_start, block_end;
        char **tokens;
        char *tokens_str;
        char *space;
        char *uuid_str;

        g_strstrip(line);

        if (strlen(line) == 0 || line[0] == '#' || line[0] == ';') {
            continue;
        }

        space = strchr(line, ' ');
        if (!space) {
            fprintf(stderr, "Failed to parse config file: %s\n", filename);
            fprintf(stderr, "Missing UUID space separator at : %s\n", line);
            exit(EXIT_FAILURE);
        }
        
        *space = '\0';
        uuid_str = line;
        tokens_str = space + 1;
        g_strstrip(tokens_str);

        tokens = g_strsplit(tokens_str, ",", -1);
        num_tokens = g_strv_length(tokens);

        if (num_tokens == 0) {
            g_strfreev(tokens);
            continue;
        }

        block_start = strtoull(tokens[0], NULL, 16);
        block_end = strtoull(tokens[num_tokens - 1], NULL, 16);

        for (int i = 0; i < num_tokens; i++) {
            uint64_t addr = 0;
            bool is_64bit = false;
            uint8_t reg = NO_REG_WATCH;
            char *cln = strchr(tokens[i], ':');
            size_t uuid_len;
            uint64_t *key;

            if (cln) {
                *cln = '\0';
                reg = parse_reg(cln + 1);
                is_64bit = (tolower(*(cln + 1)) != 'w');
            }

            addr = strtoull(tokens[i], NULL, 16);

            BranchExecData *data = g_new0(BranchExecData, 1);

            data->insn_vaddr = addr;
            data->cond_start = block_start;
            data->cond_end   = block_end;
            data->reg_idx    = reg;
            data->is_64bit   = is_64bit;
            
            memset(data->uuid, 0, UUID_SIZE);
            uuid_len = strlen(uuid_str);
            memcpy(data->uuid, uuid_str, uuid_len > UUID_SIZE ? UUID_SIZE :
                                                                uuid_len);

            key = g_new(uint64_t, 1);
            *key = addr;

            g_hash_table_insert(target_instructions, key, data);
        }

        g_strfreev(tokens);  
    }

    fclose(fp);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    if (strcmp(info->target_name, "aarch64")) {
        fprintf(stderr, "Target %s is not supported\n", info->target_name);
        return 1;
    }

    for (int i = 0; i < argc; ++i) {
        if (g_str_has_prefix(argv[i], "tracefile=")) {
            trace_file = g_strdup(argv[i] + strlen("tracefile="));
        } else if (g_str_has_prefix(argv[i], "config=")) {
            config_file = g_strdup(argv[i] + strlen("config="));
        }
    }

    if (!config_file) {
        fprintf(stderr, "ERROR: config file with branch addresses required\n");
        return 1;
    }

    load_config_file(config_file);

    cpus_btrace = g_ptr_array_new();
    g_mutex_init(&trace_lock);

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);

    return 0;
}