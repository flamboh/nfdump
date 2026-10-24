/*
 *  Copyright (c) 2009-2026, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "barrier.h"
#include "config.h"
#include "exporter.h"
#include "flist.h"
#include "ip128.h"
#include "nbar.h"
#include "nfconf.h"
#include "nfx.h"
#include "nfdump.h"
#include "nfdump_1_6_x.h"
#include "nffile.h"
#include "nfxV3.h"
#include "panonymizer.h"
#include "util.h"

#define MAXANONWORKERS 8

typedef struct worker_param_s {
    int self;
    int numWorkers;
    int anon_src;
    int anon_dst;
    dataBlock_t **dataBlock;

    // sync barrier
    pthread_control_barrier_t *barrier;
} worker_param_t;

// set by the workers, if a record can not be anonymized
static atomic_int anonError = 0;

// output file being written. Removed, if nfanon exits before it is complete
static char pendingFile[MAXPATHLEN] = {0};

// signals, which remove the pending file. Only the main thread handles them
static sigset_t termSignals;

// nfdump 1.6 records grow, when converted to V3 records. Every 1.6 extension of at least
// 4 bytes converts to at most 72 bytes, and the fixed part to at most 148 bytes.
// Convert a type 2 block in parts, which surely fit into one V3 block
#define LEGACY_V3SIZE(extensionSize) (148 + 18 * (extensionSize))
#define LEGACY_PARTSIZE (WRITE_BUFFSIZE - 65536)

// type 2 block, which is converted in parts
typedef struct legacyBlock_s {
    dataBlock_t *dataBlock;
    uint32_t offset;      // offset of the next record
    uint32_t nextRecord;  // index of the next record
} legacyBlock_t;

static legacyBlock_t legacyBlock = {0};

// extension size of the nfdump 1.6 extension maps seen so far in the current file, -1 if unknown
static int32_t legacyMapSize[MAX_EXTENSION_MAPS];

/* Function Prototypes */
static void usage(char *name);

static void RemovePendingFile(void);

static void TerminateHandler(int signal);

static void BlockSignals(int block);

static inline int AnonExporterInfo(exporter_info_record_t *exporter_record);

static inline int AnonRecord(recordHeaderV3_t *v3Record, int anon_src, int anon_dst);

static int ValidRecordSize(record_header_t *record);

static int ParseWorkerCount(const char *arg, int *numWorkers);

static void process_data(queue_t *fileList, char *wfile, int verbose, worker_param_t **workerList, int numWorkers,
                         pthread_control_barrier_t *barrier, dataBlock_t **dataBlockPtr);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-C <file>\tRead optional config file.\n"
        "-h\t\tthis text you see right here.\n"
        "-K <key>\tAnonymize IP addresses using CryptoPAn with key <key>.\n"
        "-s\t\tPreserve source address.\n"
        "-d\t\tPreserve destination address.\n"
        "-q\t\tDeprecated and rejected; use -v 0 to suppress progress output.\n"
        "-r <path>\tread input from single file or all files in directory.\n"
        "-v level\tSet verbose level.\n"
        "-w <file>\tName of output file. Defaults to input file.\n"
        "-W <num>\tOptionally set the number of workers to compress flows\n"
        "-t <num>\tLegacy alias for -W <num>.\n",
        name);
} /* usage */

static int ParseWorkerCount(const char *arg, int *numWorkers) {
    char *endPtr = NULL;
    errno = 0;
    long value = strtol(arg, &endPtr, 10);
    if (errno == ERANGE || endPtr == arg || *endPtr != '\0' || value < 0 || value > INT_MAX) return 0;

    *numWorkers = (int)value;
    return 1;
}  // End of ParseWorkerCount

static void RemovePendingFile(void) {
    if (pendingFile[0]) unlink(pendingFile);
}  // End of RemovePendingFile

static void TerminateHandler(int signal) {
    (void)signal;
    RemovePendingFile();
    _exit(255);
}  // End of TerminateHandler

// block the signals while the pending file is created or renamed
static void BlockSignals(int block) {
    pthread_sigmask(block ? SIG_BLOCK : SIG_UNBLOCK, &termSignals, NULL);
}  // End of BlockSignals

static inline int AnonExporterInfo(exporter_info_record_t *exporter_record) {
    const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

    if (exporter_record->header.size != sizeof(exporter_info_record_t)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return 0;
    }

    uint64_t anon_ip[2];

    ip128_t ipAddr;
    uint64_t *u = (uint64_t *)ipAddr.bytes;
    memcpy(ipAddr.bytes, exporter_record->ip, sizeof(ip128_t));
    switch (exporter_record->fill) {
        case 0: {  // new type of info record
            // anonymizing an IPv4/IPv6 combind record is more complicated,
            // the the anonimizer expects host order bytes and has seperate
            // functions for IPv4 and IPv6
            if (is_ipv4_mapped(&ipAddr)) {
                // anonymise IPv4
                uint32_t ipv4;
                memcpy(&ipv4, ipAddr.bytes + 12, sizeof(uint32_t));
                ipv4 = anonymize(ntohl(ipv4));
                ipv4 = htonl(ipv4);
                memcpy(ipAddr.bytes + 12, &ipv4, sizeof(uint32_t));

            } else {
                // anonymise IPv6
                u[0] = ntohll(u[0]);
                u[1] = ntohll(u[1]);
                anonymize_v6(u, anon_ip);
                u[0] = htonll(anon_ip[0]);
                u[1] = htonll(anon_ip[1]);
            }
        } break;
        case AF_INET: {  // old IPV4 record
            uint32_t ipv4 = anonymize(u[1]);

            // convert to new representation
            ipv4 = htonl(ipv4);
            memcpy(ipAddr.bytes, prefix, sizeof(prefix));
            memcpy(ipAddr.bytes + 12, &ipv4, sizeof(uint32_t));
            exporter_record->fill = 0;

            char s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ipAddr.bytes, s, INET6_ADDRSTRLEN);
            dbg_printf("Exporter: %s\n", s);
            // copy back to exporter ip
        } break;
        default: {  // old IPv6 record - like nfdump, take any other address family as IPv6
            anonymize_v6(u, anon_ip);
            u[0] = htonll(anon_ip[0]);
            u[1] = htonll(anon_ip[1]);

            // convert to new representation
            exporter_record->fill = 0;
        } break;
    }
    memcpy(exporter_record->ip, ipAddr.bytes, sizeof(ip128_t));

#ifdef DEVEL
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipAddr.bytes, s, INET6_ADDRSTRLEN);
    printf("Exporter: %s\n", s);
#endif

    return 1;
}  // End of AnonExporterInfo

// a fixed size extension must have exactly its size, as nfanon copies any surplus bytes
// unmodified. A variable length extension holds at least its fixed part
static inline int ValidExtensionLength(const elementHeader_t *elementHeader) {
    switch (elementHeader->type) {
        case EXnull:
        case EXnbarAppID:
        case EXlabelID:
        case EXinPayloadID:
        case EXoutPayloadID:
        case EXinmonFrameID:
        case EXpfinfoID:
        case EXnokiaNatStringID:
            return elementHeader->length >= extensionTable[elementHeader->type].size;
        default:
            return elementHeader->length == extensionTable[elementHeader->type].size;
    }
}  // End of ValidExtensionLength

// anonymize a V3 record. Returns 0, if the record is corrupt
static inline int AnonRecord(recordHeaderV3_t *v3Record, int anon_src, int anon_dst) {
    elementHeader_t *elementHeader;

    void *p = (void *)v3Record;
    void *eor = p + v3Record->size;

    if (v3Record->size < sizeof(recordHeaderV3_t)) {
        LogError("v3Record - unexpected size: '%u'", v3Record->size);
        return 0;
    }

    SetFlag(v3Record->flags, V3_FLAG_ANON);
    dbg_printf("Record announces %u extensions with total size %u\n", v3Record->numElements, v3Record->size);
    // first record header
    elementHeader = (elementHeader_t *)(p + sizeof(recordHeaderV3_t));
    int i;
    for (i = 0; i < v3Record->numElements; i++) {
        uint64_t anon_ip[2];
        // the extension must lie within the record and have the size of its type.
        // An unknown extension may hold addresses
        if ((void *)elementHeader + sizeof(elementHeader_t) > eor || elementHeader->type >= MAXEXTENSIONS ||
            elementHeader->length < sizeof(elementHeader_t) || !ValidExtensionLength(elementHeader) ||
            (void *)elementHeader + elementHeader->length > eor) {
            goto CORRUPT;
        }
        dbg_printf("[%i] next extension: %u: %s\n", i, elementHeader->type, extensionTable[elementHeader->type].name);
        switch (elementHeader->type) {
            case EXnull:
                // nfdump marks an unused IPv4 or IPv6 flow extension as EXnull and keeps its data
                memset((void *)elementHeader + sizeof(elementHeader_t), 0, elementHeader->length - sizeof(elementHeader_t));
                break;
            case EXgenericFlowID:
                break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) ipv4Flow->srcAddr = anonymize(ipv4Flow->srcAddr);
                if (anon_dst) ipv4Flow->dstAddr = anonymize(ipv4Flow->dstAddr);
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) {
                    anonymize_v6(ipv6Flow->srcAddr, anon_ip);
                    ipv6Flow->srcAddr[0] = anon_ip[0];
                    ipv6Flow->srcAddr[1] = anon_ip[1];
                }

                if (anon_dst) {
                    anonymize_v6(ipv6Flow->dstAddr, anon_ip);
                    ipv6Flow->dstAddr[0] = anon_ip[0];
                    ipv6Flow->dstAddr[1] = anon_ip[1];
                }
            } break;
            case EXflowMiscID:
                break;
            case EXcntFlowID:
                break;
            case EXvLanID:
                break;
            case EXasRoutingID: {
                EXasRouting_t *asRouting = (EXasRouting_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) asRouting->srcAS = 0;
                if (anon_dst) asRouting->dstAS = 0;
            } break;
            case EXbgpNextHopV4ID: {
                EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                bgpNextHopV4->ip = anonymize(bgpNextHopV4->ip);
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(bgpNextHopV6->ip, anon_ip);
                bgpNextHopV6->ip[0] = anon_ip[0];
                bgpNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipNextHopV4->ip = anonymize(ipNextHopV4->ip);
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipNextHopV6->ip, anon_ip);
                ipNextHopV6->ip[0] = anon_ip[0];
                ipNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipReceivedV4ID: {
                EXipReceivedV4_t *ipReceived = (EXipReceivedV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipReceived->ip = anonymize(ipReceived->ip);
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceived = (EXipReceivedV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipReceived->ip, anon_ip);
                ipReceived->ip[0] = anon_ip[0];
                ipReceived->ip[1] = anon_ip[1];
            } break;
            case EXmplsLabelID:
                break;
            case EXmacAddrID:
                break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)((void *)elementHeader + sizeof(elementHeader_t));
                asAdjacent->nextAdjacentAS = 0;
                asAdjacent->prevAdjacentAS = 0;
            } break;
            case EXlatencyID:
                break;
            case EXnselCommonID:
                break;
            case EXnatXlateIPv4ID: {
                EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) natXlateIPv4->xlateSrcAddr = anonymize(natXlateIPv4->xlateSrcAddr);
                if (anon_dst) natXlateIPv4->xlateDstAddr = anonymize(natXlateIPv4->xlateDstAddr);
            } break;
            case EXnatXlateIPv6ID: {
                EXnatXlateIPv6_t *natXlateIPv6 = (EXnatXlateIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) {
                    anonymize_v6(natXlateIPv6->xlateSrcAddr, anon_ip);
                    natXlateIPv6->xlateSrcAddr[0] = anon_ip[0];
                    natXlateIPv6->xlateSrcAddr[1] = anon_ip[1];
                }
                if (anon_dst) {
                    anonymize_v6(natXlateIPv6->xlateDstAddr, anon_ip);
                    natXlateIPv6->xlateDstAddr[0] = anon_ip[0];
                    natXlateIPv6->xlateDstAddr[1] = anon_ip[1];
                }
            } break;
            case EXtunIPv4ID: {
                EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) tunIPv4->tunSrcAddr = anonymize(tunIPv4->tunSrcAddr);
                if (anon_dst) tunIPv4->tunDstAddr = anonymize(tunIPv4->tunDstAddr);
            } break;
            case EXtunIPv6ID: {
                EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) {
                    anonymize_v6(tunIPv6->tunSrcAddr, anon_ip);
                    tunIPv6->tunSrcAddr[0] = anon_ip[0];
                    tunIPv6->tunSrcAddr[1] = anon_ip[1];
                }
                if (anon_dst) {
                    anonymize_v6(tunIPv6->tunDstAddr, anon_ip);
                    tunIPv6->tunDstAddr[0] = anon_ip[0];
                    tunIPv6->tunDstAddr[1] = anon_ip[1];
                }
            } break;
            case EXinPayloadID:
            case EXoutPayloadID:
            case EXinmonFrameID:
                // raw packet data contains addresses in arbitrary places - clear it
                // but keep the extension and its length
                memset((void *)elementHeader + sizeof(elementHeader_t), 0, elementHeader->length - sizeof(elementHeader_t));
                break;
                // default:
                // skip other and unknown extension
        }

        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
    }

    // bytes after the last extension would be copied unmodified
    if ((void *)elementHeader != eor) {
        LogError("Corrupt record: %u bytes after %u extensions", (unsigned)(eor - (void *)elementHeader), v3Record->numElements);
        return 0;
    }

    return 1;

CORRUPT:
    LogError("Corrupt record: extension %d of %u invalid", i + 1, v3Record->numElements);
    return 0;

}  // End of AnonRecord

// fail, if the input file is the output file
static void CheckInputAlias(nffile_t *nffile, const char *outFile) {
    struct stat in, out;
    if (fstat(nffile->fd, &in) < 0) {
        LogError("fstat() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    if (stat(outFile, &out) == 0 && in.st_dev == out.st_dev && in.st_ino == out.st_ino) {
        LogError("Input file '%s' is the output file '%s'", nffile->fileName, outFile);
        exit(255);
    }
}  // End of CheckInputAlias

// size of a record without addresses, which has a fixed layout
static int ValidRecordSize(record_header_t *record) {
    uint64_t size = 0;
    switch (record->type) {
        case ExporterStatRecordType: {
            exporter_stats_record_t *stats = (exporter_stats_record_t *)record;
            if (record->size < sizeof(exporter_stats_record_t) || stats->stat_count == 0) break;
            size = sizeof(exporter_stats_record_t) + (uint64_t)(stats->stat_count - 1) * sizeof(struct exporter_stat_s);
        } break;
        case SamplerLegacyRecordType:
            size = sizeof(samplerV0_record_t);
            break;
        case SamplerRecordType:
            size = sizeof(sampler_record_t);
            break;
    }
    if (record->size == size) return 1;

    LogError("Corrupt record type %u with size %u", record->type, record->size);
    return 0;
}  // End of ValidRecordSize

// open the next input file. Unlike GetNextFile(), fail on a file, which can not be opened
static nffile_t *OpenNextFile(queue_t *fileList) {
    char *fileName = queue_pop(fileList);
    if (fileName == QUEUE_CLOSED) return NULL;

    nffile_t *nffile = OpenFile(fileName);
    if (!nffile) {
        LogError("Failed to open input file '%s'", fileName);
        exit(255);
    }
    free(fileName);
    return nffile;
}  // End of OpenNextFile

// size of a nfdump 1.6 record converted to V3. Fails on corrupt records
static uint32_t LegacyRecordSize(record_header_t *record, const char *fileName) {
    switch (record->type) {
        case ExtensionMapType: {
            extension_map_t *map = (extension_map_t *)record;
            if (record->size < sizeof(extension_map_t)) break;
            legacyMapSize[map->map_id] = map->extension_size;
            return 0;
        }
        case CommonRecordType: {
            common_record_t *commonRecord = (common_record_t *)record;
            if (record->size < sizeof(common_record_t) || legacyMapSize[commonRecord->ext_map] < 0) break;
            uint32_t size = offsetof(common_record_t, data);
            size += TestFlag(commonRecord->flags, FLAG_IPV6_ADDR) ? 4 * sizeof(uint64_t) : 2 * sizeof(uint32_t);
            size += TestFlag(commonRecord->flags, FLAG_PKG_64) ? sizeof(uint64_t) : sizeof(uint32_t);
            size += TestFlag(commonRecord->flags, FLAG_BYTES_64) ? sizeof(uint64_t) : sizeof(uint32_t);
            size += legacyMapSize[commonRecord->ext_map];
            // the record must hold exactly the extensions of its map
            if (record->size != size || record->size > 2048) break;
            return LEGACY_V3SIZE(legacyMapSize[commonRecord->ext_map]);
        }
        case ExporterInfoRecordType:
        case ExporterStatRecordType:
        case SamplerLegacyRecordType:
            // copied unmodified
            return record->size;
    }
    LogError("Can not convert nfdump 1.6 record type %u with size %u in '%s'", record->type, record->size, fileName);
    exit(255);
}  // End of LegacyRecordSize

// each file defines its own extension maps
static void ResetLegacyMaps(void) {
    for (int i = 0; i < MAX_EXTENSION_MAPS; i++) legacyMapSize[i] = -1;
    ResetCompat16();
}  // End of ResetLegacyMaps

// convert the next records of a type 2 block into a V3 block. Returns NULL at the end of the block
static dataBlock_t *ConvertLegacyBlock(legacyBlock_t *legacy, const char *fileName) {
    dataBlock_t *dataBlock = legacy->dataBlock;
    if (legacy->nextRecord == dataBlock->NumRecords) {
        if (legacy->offset != dataBlock->size) {
            LogError("Corrupt data file. %u bytes after the last record in '%s'", dataBlock->size - legacy->offset, fileName);
            exit(255);
        }
        return NULL;
    }

    dataBlock_t *v3Block = NewDataBlock();
    dataBlock_t *partBlock = NewDataBlock();
    if (!v3Block || !partBlock) exit(255);

    // convert parts of records, which surely fit into the space left in the V3 block
    while (legacy->nextRecord < dataBlock->NumRecords) {
        partBlock->NumRecords = 0;
        partBlock->size = 0;
        partBlock->type = DATA_BLOCK_TYPE_2;

        uint32_t v3Size = v3Block->size;
        uint32_t v3Records = 0;
        while (legacy->nextRecord < dataBlock->NumRecords) {
            record_header_t *record = (record_header_t *)(GetCursor(dataBlock) + legacy->offset);
            if (legacy->offset + sizeof(record_header_t) > dataBlock->size || record->size < sizeof(record_header_t) ||
                legacy->offset + record->size > dataBlock->size) {
                LogError("Corrupt data file. Inconsistent block size in '%s'", fileName);
                exit(255);
            }
            uint32_t size = LegacyRecordSize(record, fileName);
            if (v3Size + size > LEGACY_PARTSIZE) break;

            memcpy(GetCurrentCursor(partBlock), record, record->size);
            partBlock->size += record->size;
            partBlock->NumRecords++;
            v3Size += size;
            if (record->type != ExtensionMapType) v3Records++;

            legacy->offset += record->size;
            legacy->nextRecord++;
        }
        // V3 block full
        if (partBlock->NumRecords == 0) break;

        uint32_t numRecords = v3Block->NumRecords;
        ConvertBlockType2(partBlock, v3Block);

        // the conversion skips records, which it can not convert
        if (v3Block->NumRecords - numRecords != v3Records) {
            LogError("Failed to convert nfdump 1.6 records in '%s': %u of %u converted", fileName, v3Block->NumRecords - numRecords,
                     v3Records);
            exit(255);
        }
    }
    FreeDataBlock(partBlock);
    return v3Block;
}  // End of ConvertLegacyBlock

// read the next data block and convert nfdump 1.6 blocks. Fail on a truncated or corrupt input file
static dataBlock_t *NextBlock(nffile_t *nffile, uint32_t *blockCount) {
    while (1) {
        if (legacyBlock.dataBlock) {
            dataBlock_t *v3Block = ConvertLegacyBlock(&legacyBlock, nffile->fileName);
            if (v3Block && v3Block->NumRecords) return v3Block;
            if (v3Block) {
                FreeDataBlock(v3Block);
                continue;
            }
            FreeDataBlock(legacyBlock.dataBlock);
            legacyBlock.dataBlock = NULL;
        }

        dataBlock_t *dataBlock = ReadBlock(nffile, NULL);
        if (!dataBlock) {
            if (*blockCount != nffile->file_header->NumBlocks) {
                LogError("Failed to read input file '%s': %u of %u blocks read", nffile->fileName, *blockCount,
                         nffile->file_header->NumBlocks);
                exit(255);
            }
            return NULL;
        }
        (*blockCount)++;
        if (dataBlock->type != DATA_BLOCK_TYPE_2) return dataBlock;

        // nfdump 1.6.x records - the workers anonymize V3 records only
        legacyBlock = (legacyBlock_t){.dataBlock = dataBlock, .offset = 0, .nextRecord = 0};
    }
}  // End of NextBlock

// finish the output file and rename it to finalName, if given
static void CloseOutputFile(nffile_t *nffile, const char *outFile, const char *finalName) {
    if (!FlushFile(nffile)) {
        LogError("Failed to write output file '%s'", outFile);
        exit(255);
    }
    DisposeFile(nffile);

    BlockSignals(1);
    if (finalName && rename(outFile, finalName) < 0) {
        LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    pendingFile[0] = '\0';
    BlockSignals(0);
}  // End of CloseOutputFile

// all errors are fatal: nfanon exits and RemovePendingFile() removes the incomplete output file
static void process_data(queue_t *fileList, char *wfile, int verbose, worker_param_t **workerList, int numWorkers,
                         pthread_control_barrier_t *barrier, dataBlock_t **dataBlockPtr) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    char outFile[MAXPATHLEN];
    char *cfile = NULL;
    // -w names an existing file. Write a new file and replace it, when complete
    int replaceOutput = 0;

    int cnt = 1;
    uint32_t blockCount = 0;
    nffile_t *nffile_r = NULL;
    nffile_t *nffile_w = NULL;

    dataBlock_t *nextBlock = NULL;
    // map datablock for workers - all workers
    // process the same block but different records
    // dataBlockPtr lives in the caller's frame (main()), which outlives every worker
    // thread - workers only stop dereferencing it once WaitWorkersDone() has joined them
    *dataBlockPtr = NULL;
    for (int i = 0; i < numWorkers; i++) {
        // set new datablock for all workers
        workerList[i]->dataBlock = dataBlockPtr;
    }

    // wait for workers ready to start
    pthread_controller_wait(barrier);

    int blk_count = 0;
    int done = 0;
    while (!done) {
        // get next data block
        *dataBlockPtr = nextBlock;
        if (*dataBlockPtr == NULL) {
            /* Without -w, finish and replace each input file separately.
             * With -w, keep the writer open and append every input file. */
            if (nffile_w && wfile == NULL) {
                CloseOutputFile(nffile_w, outFile, cfile);
                nffile_w = NULL;
            }

            if (nffile_r) DisposeFile(nffile_r);
            nffile_r = OpenNextFile(fileList);
            if (nffile_r == NULL) {
                if (nffile_w) {
                    CloseOutputFile(nffile_w, outFile, replaceOutput ? wfile : NULL);
                    nffile_w = NULL;
                }
                done = 1;
                printf("\nDone\n");
                continue;
            }

            cfile = nffile_r->fileName;
            if (!cfile) {
                LogError("(NULL) input file name error in %s line %d", __FILE__, __LINE__);
                exit(255);
            }
            if (verbose) printf("  %i Processing %s\r", cnt++, cfile);
            ResetLegacyMaps();

            if (wfile == NULL || nffile_w == NULL) {
                int len;
                if (wfile == NULL) {
                    // prepare output file
                    len = snprintf(outFile, sizeof(outFile), "%s-tmp", cfile);
                } else {
                    // never write into an existing file, which may be an input file
                    struct stat st;
                    replaceOutput = stat(wfile, &st) == 0 && S_ISREG(st.st_mode);
                    len = snprintf(outFile, sizeof(outFile), replaceOutput ? "%s-tmp" : "%s", wfile);
                }
                if (len < 0 || len >= (int)sizeof(outFile)) {
                    LogError("Output file name too long");
                    exit(255);
                }
                CheckInputAlias(nffile_r, outFile);

                BlockSignals(1);
                nffile_w = OpenNewFile(outFile, CREATOR_NFANON, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
                if (!nffile_w) {
                    // can not create output file
                    exit(255);
                }
                snprintf(pendingFile, sizeof(pendingFile), "%s", outFile);
                BlockSignals(0);

                SetIdent(nffile_w, FILE_IDENT(nffile_r));
                memcpy(nffile_w->stat_record, nffile_r->stat_record, sizeof(stat_record_t));
            } else {
                CheckInputAlias(nffile_r, outFile);
                SumStatRecords(nffile_w->stat_record, nffile_r->stat_record);
            }

            // read first block from next file
            blockCount = 0;
            nextBlock = NextBlock(nffile_r, &blockCount);
            continue;
        }

        if (verbose) {
            printf("\r%c", spinner[blk_count & 0x3]);
            blk_count++;
        }

        if ((*dataBlockPtr)->type != DATA_BLOCK_TYPE_3) {
            LogError("Can not anonymize block type %u in '%s'", (*dataBlockPtr)->type, cfile);
            exit(255);
        }

        dbg_printf("Next block: %d, Records: %u\n", blk_count, (*dataBlockPtr)->NumRecords);
        // release workers from barrier
        pthread_control_barrier_release(barrier);

        // prefetch next block
        nextBlock = NextBlock(nffile_r, &blockCount);

        // wait for all workers, work done on previous block
        pthread_controller_wait(barrier);

        if (atomic_load(&anonError)) {
            LogError("Failed to anonymize '%s'", cfile);
            exit(255);
        }

        // write modified block
        if (!FlushBlock(nffile_w, *dataBlockPtr)) {
            LogError("Failed to write output file '%s'", outFile);
            exit(255);
        }

    }  // while

    // done! - signal all workers to terminate
    *dataBlockPtr = NULL;
    pthread_control_barrier_release(barrier);

    if (verbose) LogError("Processed %i files", --cnt);

}  // End of process_data

static void *worker_thread(void *arg) {
    worker_param_t *worker_param = (worker_param_t *)arg;

    uint32_t self = worker_param->self;
    uint32_t numWorkers = worker_param->numWorkers;

    // wait in barrier after launch
    pthread_control_barrier_wait(worker_param->barrier);

    while (*(worker_param->dataBlock)) {
        dataBlock_t *dataBlock = *(worker_param->dataBlock);
        dbg_printf("Worker %i working on %p\n", self, dataBlock);

        uint32_t recordCount = 0;

        record_header_t *record_ptr = GetCursor(dataBlock);
        uint32_t sumSize = 0;
        for (uint32_t i = 0; i < dataBlock->NumRecords; i++) {
            if ((sumSize + sizeof(record_header_t)) > dataBlock->size || (sumSize + record_ptr->size) > dataBlock->size ||
                (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                atomic_store(&anonError, 1);
                goto SKIP;
            }
            sumSize += record_ptr->size;

            // check, if this is our record
            if ((i % numWorkers) == self) {
                // our record - work on it
                recordCount++;

                // work on our record
                int ok = 1;
                switch (record_ptr->type) {
                    case V3Record:
                        ok = AnonRecord((recordHeaderV3_t *)record_ptr, worker_param->anon_src, worker_param->anon_dst);
                        break;
                    case ExporterInfoRecordType:
                        ok = AnonExporterInfo((exporter_info_record_t *)record_ptr);
                        break;
                    case ExporterStatRecordType:
                    case SamplerLegacyRecordType:
                    case SamplerRecordType:
                        // records without addresses. Surplus bytes would be copied unmodified
                        ok = ValidRecordSize(record_ptr);
                        break;
                    case NbarRecordType:
                    case IfNameRecordType:
                    case VrfNameRecordType:
                        // names without addresses
                        break;
                    case SlackRecord:
                        memset((void *)record_ptr + sizeof(record_header_t), 0, record_ptr->size - sizeof(record_header_t));
                        break;
                    default:
                        // a record, which can not be anonymized must not be written
                        LogError("Can not anonymize record type %u", record_ptr->type);
                        ok = 0;
                }
                if (!ok) {
                    atomic_store(&anonError, 1);
                    goto SKIP;
                }
            }
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

        // bytes after the last record would be written unmodified
        if (sumSize != dataBlock->size) {
            LogError("Corrupt data file. %u bytes after %u records in %s line %d", dataBlock->size - sumSize, dataBlock->NumRecords, __FILE__,
                     __LINE__);
            atomic_store(&anonError, 1);
        }

        dbg_printf("Worker %i: datablock completed. Records processed: %u\n", self, recordCount);

    SKIP:
        // Done
        // wait in barrier for next data record
        pthread_control_barrier_wait(worker_param->barrier);
    }

    dbg_printf("Worker %d done.\n", worker_param->self);
    free(worker_param);
    pthread_exit(NULL);
}  // End of worker_thread

static worker_param_t **LauchWorkers(pthread_t *tid, int numWorkers, int anon_src, int anon_dst, pthread_control_barrier_t *barrier) {
    worker_param_t **workerList = calloc(numWorkers, sizeof(worker_param_t *));
    if (!workerList) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    for (int i = 0; i < numWorkers; i++) {
        worker_param_t *worker_param = calloc(1, sizeof(worker_param_t));
        if (!worker_param) {
            LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        worker_param->barrier = barrier;
        worker_param->self = i;
        worker_param->anon_src = anon_src;
        worker_param->anon_dst = anon_dst;
        worker_param->dataBlock = NULL;
        worker_param->numWorkers = numWorkers;
        workerList[i] = worker_param;

        int err = pthread_create(&(tid[i]), NULL, worker_thread, (void *)worker_param);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            return NULL;
        }
    }
    return workerList;

}  // End of LaunchWorkers

static void WaitWorkersDone(pthread_t *tid, int numWorkers) {
    // wait for all nfwriter threads to exit
    for (int i = 0; i < numWorkers; i++) {
        if (tid[i]) {
            int err = pthread_join(tid[i], NULL);
            if (err) {
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            }
            tid[i] = 0;
        }
    }
}  // End of WaitWorkersDone

int main(int argc, char **argv) {
    char *wfile = NULL;
    char CryptoPAnKey[32] = {0};
    flist_t flist = {0};

    char *configFile = NULL;
    int numWorkers = 0;
    int verbose = -1;
    int anon_src = 1;
    int anon_dst = 1;
    int c;
    while ((c = getopt(argc, argv, "C:hsdK:qr:t:v:w:W:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'C':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, NOCONF) == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'K':
                CheckArgLen(optarg, 66);
                if (!ParseCryptoPAnKey(optarg, CryptoPAnKey)) {
                    LogError("Invalid key '%s' for CryptoPAn", optarg);
                    exit(255);
                }
                PAnonymizer_Init((uint8_t *)CryptoPAnKey);
                break;
            case 's':
                anon_src = 0;
                break;
            case 'd':
                anon_dst = 0;
                break;
            case 'q':
                LogError("Option -q deprecated. Use -v 0");
                exit(EXIT_FAILURE);
                verbose = 0;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                if (TestPath(optarg, S_IFREG) == PATH_OK) {
                    flist.single_file = strdup(optarg);
                } else if (TestPath(optarg, S_IFDIR) == PATH_OK) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("%s is not a file or directory", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'v':
                verbose = ParseVerbose(verbose, optarg);
                if (verbose < 0) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            case 't':
                // legacy option - fall through
                LogError("Legacy option. Use -W <num> to select the number of workers");
            case 'W':
                CheckArgLen(optarg, 16);
                if (!ParseWorkerCount(optarg, &numWorkers)) {
                    LogError("Invalid number of working threads: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                usage(argv[0]);
                exit(255);
        }
    }

    if (!InitLog(NOSYSLOG, argv[0], NULL, verbose)) {
        exit(EXIT_FAILURE);
    }

    if (CryptoPAnKey[0] == '\0') {
        LogError("Expect -K <key>");
        usage(argv[0]);
        exit(255);
    }

    if ((anon_src + anon_dst) == 0) {
        LogError("Preserving src IP and dst IP does not make sense for nfanon");
        usage(argv[0]);
        exit(255);
    }

    if (ConfOpen(configFile, "nfanon") < 0) exit(EXIT_FAILURE);

    // check numWorkers depending on cores online
    numWorkers = GetNumWorkers(numWorkers);

    // all threads but the main thread block the signals, which remove the pending file
    sigemptyset(&termSignals);
    sigaddset(&termSignals, SIGTERM);
    sigaddset(&termSignals, SIGINT);
    sigaddset(&termSignals, SIGHUP);
    // SIGABRT for a failed assertion in the nfdump 1.6 conversion code
    sigaddset(&termSignals, SIGABRT);
    BlockSignals(1);

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(numWorkers, fileList)) exit(255);

    pthread_control_barrier_t *barrier = pthread_control_barrier_init(numWorkers);
    if (!barrier) exit(255);

    pthread_t *tid = calloc(numWorkers, sizeof(pthread_t));
    if (!tid) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    dbg_printf("Launch Workers\n");
    worker_param_t **workerList = LauchWorkers(tid, numWorkers, anon_src, anon_dst, barrier);
    if (!workerList) {
        LogError("Failed to launch workers");
        exit(255);
    }

    // make stdout unbuffered for progress pointer
    setvbuf(stdout, (char *)NULL, _IONBF, 0);
    // dataBlock is declared here, not inside process_data(), so its lifetime covers the
    // whole time worker threads may still dereference it - up through WaitWorkersDone()
    dataBlock_t *dataBlock = NULL;

    atexit(RemovePendingFile);
    struct sigaction act = {.sa_handler = TerminateHandler, .sa_mask = termSignals};
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGABRT, &act, NULL);
    // a file size limit is a write error
    signal(SIGXFSZ, SIG_IGN);
    BlockSignals(0);
    process_data(fileList, wfile, verbose, workerList, numWorkers, barrier, &dataBlock);

    WaitWorkersDone(tid, numWorkers);
    pthread_control_barrier_destroy(barrier);

    free(tid);
    free(workerList);

    return 0;
}
