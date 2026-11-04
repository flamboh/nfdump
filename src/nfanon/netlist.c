/*
 *  Copyright (c) 2026, Oliver Boorstein
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

#include "netlist.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"
#include "nfdump.h"
#include "util.h"

#define MARK_NONE -1
#define MARK_ANON 1

// binary trie, one bit per level. Node 0 is unused and marks a missing child
typedef struct netNode_s {
    uint32_t child[2];
    int32_t mark;
} netNode_t;

struct netList_s {
    netNode_t *node;
    uint32_t numNodes;
    uint32_t maxNodes;
    uint32_t root[2];  // [0] IPv4, [1] IPv6
    uint32_t numAnon;
};

static uint32_t NewNode(netList_t *netList) {
    if (netList->numNodes == netList->maxNodes) {
        uint32_t maxNodes = netList->maxNodes ? 2 * netList->maxNodes : 1024;
        netNode_t *node = realloc(netList->node, maxNodes * sizeof(netNode_t));
        if (!node) {
            LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return 0;
        }
        netList->node = node;
        netList->maxNodes = maxNodes;
    }
    uint32_t n = netList->numNodes++;
    netList->node[n].child[0] = 0;
    netList->node[n].child[1] = 0;
    netList->node[n].mark = MARK_NONE;
    return n;
}  // End of NewNode

static inline int GetBit(const uint64_t ip[2], int bit) { return (ip[bit >> 6] >> (63 - (bit & 0x3F))) & 1; }

// returns the mark of the longest matching prefix
static inline int Lookup(const netList_t *netList, uint32_t n, const uint64_t ip[2], int bits) {
    const netNode_t *node = netList->node;
    int mark = node[n].mark;
    for (int i = 0; i < bits; i++) {
        n = node[n].child[GetBit(ip, i)];
        if (n == 0) break;
        if (node[n].mark != MARK_NONE) mark = node[n].mark;
    }
    return mark;
}  // End of Lookup

int NetListMatchV4(const netList_t *netList, uint32_t ip) {
    uint64_t key[2] = {(uint64_t)ip << 32, 0};
    return Lookup(netList, netList->root[0], key, 32) == MARK_ANON;
}  // End of NetListMatchV4

int NetListMatchV6(const netList_t *netList, const uint64_t ip[2]) {
    // IPv4-mapped addresses are decided by the IPv4 networks
    if (ip[0] == 0 && (ip[1] >> 32) == 0xFFFF) return NetListMatchV4(netList, (uint32_t)ip[1]);
    return Lookup(netList, netList->root[1], ip, 128) == MARK_ANON;
}  // End of NetListMatchV6

// insert prefix. Returns 1 on success, 0 on memory error
static int Insert(netList_t *netList, int family, const uint64_t ip[2], int prefixLen, int mark) {
    uint32_t n = netList->root[family];
    for (int i = 0; i < prefixLen; i++) {
        int bit = GetBit(ip, i);
        uint32_t next = netList->node[n].child[bit];
        if (next == 0) {
            next = NewNode(netList);
            if (next == 0) return 0;
            netList->node[n].child[bit] = next;
        }
        n = next;
    }
    netList->node[n].mark = mark;
    return 1;
}  // End of Insert

// parse a single line. Returns 1 on success, 0 on error
static int ParseLine(netList_t *netList, const char *fileName, unsigned lineNum, char *line) {
    char *s = line;

    char *comment = strchr(s, '#');
    if (comment) *comment = '\0';

    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) e--;
    *e = '\0';
    if (*s == '\0') return 1;

    if (*s == '!') {
        LogError("%s line %u: '!' preserve entries are not supported, every listed network is anonymized", fileName, lineNum);
        return 0;
    }

    char *net = s;
    int maxLen;
    int family;
    uint64_t ip[2] = {0, 0};

    char *slash = strchr(net, '/');
    if (slash) *slash = '\0';

    uint32_t ipv4;
    uint64_t ipv6[2];
    if (inet_pton(AF_INET, net, &ipv4) == 1) {
        family = 0;
        maxLen = 32;
        ip[0] = (uint64_t)ntohl(ipv4) << 32;
    } else if (inet_pton(AF_INET6, net, ipv6) == 1) {
        family = 1;
        maxLen = 128;
        ip[0] = ntohll(ipv6[0]);
        ip[1] = ntohll(ipv6[1]);
    } else {
        LogError("%s line %u: invalid network address '%s'", fileName, lineNum, net);
        return 0;
    }

    int prefixLen = maxLen;
    if (slash) {
        char *p = slash + 1;
        if (*p == '\0' || strlen(p) > 3) {
            LogError("%s line %u: invalid prefix length '%s'", fileName, lineNum, p);
            return 0;
        }
        prefixLen = 0;
        for (; *p; p++) {
            if (!isdigit((unsigned char)*p)) {
                LogError("%s line %u: invalid prefix length '%s'", fileName, lineNum, slash + 1);
                return 0;
            }
            prefixLen = 10 * prefixLen + (*p - '0');
        }
        if (prefixLen > maxLen) {
            LogError("%s line %u: prefix length %d out of range", fileName, lineNum, prefixLen);
            return 0;
        }
    }

    // reject host bits set beyond the prefix length - most likely a typo
    for (int i = prefixLen; i < 128; i++) {
        if (GetBit(ip, i)) {
            LogError("%s line %u: host bits set in network '%s/%d'", fileName, lineNum, net, prefixLen);
            return 0;
        }
    }

    // an IPv4-mapped network ::ffff:a.b.c.d/n is the IPv4 network a.b.c.d/n-96
    if (family == 1 && prefixLen >= 96 && ip[0] == 0 && (ip[1] >> 32) == 0xFFFF) {
        family = 0;
        ip[0] = (ip[1] & 0xFFFFFFFF) << 32;
        ip[1] = 0;
        prefixLen -= 96;
    }

    if (!Insert(netList, family, ip, prefixLen, MARK_ANON)) return 0;
    netList->numAnon++;

    return 1;
}  // End of ParseLine

netList_t *NetListLoad(const char *fileName) {
    FILE *fp = fopen(fileName, "r");
    if (!fp) {
        LogError("Failed to open network list '%s': %s", fileName, strerror(errno));
        return NULL;
    }

    netList_t *netList = calloc(1, sizeof(netList_t));
    if (!netList) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        fclose(fp);
        return NULL;
    }

    // node 0 is the null node
    if (NewNode(netList) != 0 || (netList->root[0] = NewNode(netList)) == 0 || (netList->root[1] = NewNode(netList)) == 0) {
        NetListFree(netList);
        fclose(fp);
        return NULL;
    }

    char *line = NULL;
    size_t lineSize = 0;
    unsigned lineNum = 0;
    int ok = 1;
    while (ok && getline(&line, &lineSize, fp) != -1) {
        lineNum++;
        ok = ParseLine(netList, fileName, lineNum, line);
    }
    if (ok && ferror(fp)) {
        LogError("Failed to read network list '%s': %s", fileName, strerror(errno));
        ok = 0;
    }
    free(line);
    fclose(fp);

    if (ok && netList->numAnon == 0) {
        LogError("Network list '%s' contains no networks to anonymize", fileName);
        ok = 0;
    }

    if (!ok) {
        NetListFree(netList);
        return NULL;
    }

    return netList;
}  // End of NetListLoad

void NetListFree(netList_t *netList) {
    if (!netList) return;
    free(netList->node);
    free(netList);
}  // End of NetListFree
