/*
 * Atlantis Flow Stream v1 output.
 *
 * The wire format is deliberately assembled byte by byte. The nfdump
 * extension structs are host-layout implementation details and must not leak
 * into the process protocol.
 */

#include "output_atlantis.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nfxV3.h"
#include "util.h"

#define ATLANTIS_RECORD_LEN 72U
#define ATLANTIS_BLOCK_CAPACITY 2048U
#define ATLANTIS_MAX_SIGNED ((uint64_t)INT64_MAX)

static uint8_t block_payload[ATLANTIS_BLOCK_CAPACITY * ATLANTIS_RECORD_LEN];
static uint32_t block_count;
static uint64_t emitted_record_count;
static FILE *output_stream;
static bool output_failed;

static void put_le_u16(uint8_t *destination, uint16_t value) {
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
}

static void put_le_u32(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

static void put_le_u64(uint8_t *destination, uint64_t value) {
    for (uint32_t i = 0; i < sizeof(value); i++) {
        destination[i] = (uint8_t)(value >> (i * 8));
    }
}

static void fail_output(const char *message) {
    output_failed = true;
    if (emitted_record_count != 0) {
        LogError("Atlantis output after record %" PRIu64 ": %s", emitted_record_count, message);
    } else {
        LogError("Atlantis output: %s", message);
    }
    exit(EXIT_FAILURE);
}

static void fail_record(recordHandle_t *recordHandle, const char *message) {
    output_failed = true;
    LogError("Atlantis output record %" PRIu64 ": %s", recordHandle->flowCount, message);
    exit(EXIT_FAILURE);
}

static void write_bytes(const void *data, size_t length) {
    if (fwrite(data, 1, length, output_stream) != length) {
        int saved_errno = errno;
        char message[256];
        snprintf(message, sizeof(message), "write failed: %s", saved_errno ? strerror(saved_errno) : "short write");
        fail_output(message);
    }
}

static void flush_block(void) {
    if (block_count == 0) return;

    uint8_t count[sizeof(uint32_t)];
    put_le_u32(count, block_count);
    write_bytes(count, sizeof(count));
    write_bytes(block_payload, (size_t)block_count * ATLANTIS_RECORD_LEN);
    block_count = 0;
}

static void encode_address(uint8_t *destination, recordHandle_t *recordHandle, uint8_t *tag) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        uint32_t source = htonl(ipv4Flow->srcAddr);
        uint32_t destinationAddress = htonl(ipv4Flow->dstAddr);
        memcpy(destination, &source, sizeof(source));
        memcpy(destination + 16, &destinationAddress, sizeof(destinationAddress));
        return;
    }

    if (ipv6Flow) {
        uint64_t source[2] = {htonll(ipv6Flow->srcAddr[0]), htonll(ipv6Flow->srcAddr[1])};
        uint64_t destinationAddress[2] = {htonll(ipv6Flow->dstAddr[0]), htonll(ipv6Flow->dstAddr[1])};
        memcpy(destination, source, sizeof(source));
        memcpy(destination + 16, destinationAddress, sizeof(destinationAddress));
        *tag |= 1;
    }
}

static void encode_record(uint8_t *destination, recordHandle_t *recordHandle, bool syntheticTunnel) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    EXgenericFlow_t genericNull = {0};
    if (!genericFlow) genericFlow = &genericNull;

    if (genericFlow->msecFirst > ATLANTIS_MAX_SIGNED || genericFlow->msecLast > ATLANTIS_MAX_SIGNED || genericFlow->msecReceived > ATLANTIS_MAX_SIGNED) {
        fail_record(recordHandle, "timestamp exceeds signed 64-bit range");
    }
    if (genericFlow->msecLast < genericFlow->msecFirst) {
        fail_record(recordHandle, "last timestamp precedes first timestamp");
    }
    if (genericFlow->inPackets > ATLANTIS_MAX_SIGNED || genericFlow->inBytes > ATLANTIS_MAX_SIGNED) {
        fail_record(recordHandle, "counter exceeds signed 64-bit range");
    }

    uint64_t flowCount = 1;
    if (!syntheticTunnel && cntFlow) flowCount = cntFlow->flows;
    if (flowCount == 0) fail_record(recordHandle, "flow count is zero");
    if (flowCount > ATLANTIS_MAX_SIGNED) fail_record(recordHandle, "flow count exceeds signed 64-bit range");

    uint8_t minTTL = 0;
    uint8_t maxTTL = 0;
    if (!syntheticTunnel && ipInfo) {
        minTTL = ipInfo->minTTL;
        maxTTL = ipInfo->maxTTL;
    }
    if (minTTL != 0 && maxTTL != 0 && minTTL > maxTTL) {
        fail_record(recordHandle, "minimum TTL exceeds maximum TTL");
    }

    memset(destination, 0, ATLANTIS_RECORD_LEN);
    uint8_t tag = 0;
    encode_address(destination, recordHandle, &tag);

    // srcTos's low two bits are the existing ATLANTIS visibility contract:
    // bit 1 is source anonymized and bit 0 is destination anonymized. The
    // wire tag gives those independent flags their explicit bit positions.
    if (genericFlow->srcTos & 2) tag |= 2;
    if (genericFlow->srcTos & 1) tag |= 4;

    put_le_u64(destination + 32, genericFlow->inPackets);
    put_le_u64(destination + 40, genericFlow->inBytes);
    put_le_u64(destination + 48, flowCount);
    put_le_u64(destination + 56, genericFlow->msecLast - genericFlow->msecFirst);
    put_le_u16(destination + 64, genericFlow->srcPort);
    put_le_u16(destination + 66, (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) ? 0 : genericFlow->dstPort);
    destination[68] = genericFlow->proto;
    destination[69] = tag;
    destination[70] = minTTL;
    destination[71] = maxTTL;
}

void atlantis_prolog(outputParams_t *outputParam) {
    UNUSED(outputParam);
    output_stream = stdout;
    block_count = 0;
    emitted_record_count = 0;
    output_failed = false;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) fail_output("could not ignore SIGPIPE");

    uint8_t header[12] = {'A', 'T', 'L', 'N', 'F', 'L', 'O', 'W', 0, 0, 0, 0};
    put_le_u16(header + 8, 1);
    put_le_u16(header + 10, ATLANTIS_RECORD_LEN);
    write_bytes(header, sizeof(header));
}

void atlantis_epilog(outputParams_t *outputParam) {
    UNUSED(outputParam);
    if (output_failed) return;

    flush_block();
    uint8_t terminator[sizeof(uint32_t)] = {0};
    write_bytes(terminator, sizeof(terminator));
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fail_output("flush failed");
    }
}

void atlantis_record(FILE *stream, recordHandle_t *recordHandle, outputParams_t *outputParam) {
    UNUSED(outputParam);
    if (output_stream == NULL) output_stream = stream;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];

    if (genericFlow && (tunIPv4 || tunIPv6)) {
        EXgenericFlow_t tunnelGeneric = *genericFlow;
        EXipv4Flow_t tunnelIPv4 = {0};
        EXipv6Flow_t tunnelIPv6 = {0};
        recordHandle_t tunnelRecord = {0};
        tunnelRecord.flowCount = recordHandle->flowCount;
        tunnelRecord.extensionList[EXgenericFlowID] = &tunnelGeneric;

        if (tunIPv4) {
            if (tunIPv4->tunProto > UINT8_MAX) fail_record(recordHandle, "tunnel protocol exceeds 8-bit range");
            tunnelGeneric.proto = (uint8_t)tunIPv4->tunProto;
            tunnelIPv4.srcAddr = tunIPv4->tunSrcAddr;
            tunnelIPv4.dstAddr = tunIPv4->tunDstAddr;
            tunnelRecord.extensionList[EXipv4FlowID] = &tunnelIPv4;
        } else {
            if (tunIPv6->tunProto > UINT8_MAX) fail_record(recordHandle, "tunnel protocol exceeds 8-bit range");
            tunnelGeneric.proto = (uint8_t)tunIPv6->tunProto;
            tunnelIPv6.srcAddr[0] = tunIPv6->tunSrcAddr[0];
            tunnelIPv6.srcAddr[1] = tunIPv6->tunSrcAddr[1];
            tunnelIPv6.dstAddr[0] = tunIPv6->tunDstAddr[0];
            tunnelIPv6.dstAddr[1] = tunIPv6->tunDstAddr[1];
            tunnelRecord.extensionList[EXipv6FlowID] = &tunnelIPv6;
        }

        uint8_t record[ATLANTIS_RECORD_LEN];
        encode_record(record, &tunnelRecord, true);
        if (block_count == ATLANTIS_BLOCK_CAPACITY) flush_block();
        memcpy(block_payload + (size_t)block_count * ATLANTIS_RECORD_LEN, record, sizeof(record));
        block_count++;
        emitted_record_count++;
    }

    uint8_t record[ATLANTIS_RECORD_LEN];
    encode_record(record, recordHandle, false);
    if (block_count == ATLANTIS_BLOCK_CAPACITY) flush_block();
    memcpy(block_payload + (size_t)block_count * ATLANTIS_RECORD_LEN, record, sizeof(record));
    block_count++;
    emitted_record_count++;
}
