#include <data/mach-o/binary.h>
#include <data/find.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <list>
#include <unordered_map>
#include <map>
#include <set>
#include <iostream>
#include <algorithm>
#include <vector>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <math.h>
using namespace std;

enum {
    FULL_HASH,
    BEGINNING_HASH,
    ENDING_HASH
};

static int hashMode = FULL_HASH;

struct Edge;

// todo: after changing data, implement this there
static bool b_in_vmrange(const struct binary *binary, addr_t addr) {
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            auto s = (struct segment_command *) cmd;
            if(addr - s->vmaddr < s->vmsize) return true;
        }
    }
    return false;
}
static uint32_t signExtend(uint32_t val, int bits) {
    if(val & (1 << (bits - 1))) {
        val |= ~((1 << bits) - 1);
    }
    return val;
}

enum {
    INCOMPLETE_FUNC = 0,
    THUMB_FUNC,
    THUMB_VARARGS_FUNC,
    THUMB_ACCESSOR_FUNC
};

// misnomer-- it's actually any symbol
struct Function {
    vector<Edge *> forward, backward;

    uint16_t *start, *end, *endOfWorld;
    addr_t startAddr;
    const char *name;
    uint32_t hash;

    list<pair<pair<addr_t, addr_t>, bool>> refs;// the bool is whether it's a function

    int type;

    Function(uint16_t *start, uint16_t *end, uint16_t *endOfWorld, addr_t startAddr, const char *name, int type)
    : start(start), end(end), endOfWorld(endOfWorld), startAddr(startAddr), name(name), type(type) {
        if(start && !end) {
            parse();
        }
        setHash();
    }

    void parse() {
        auto addr = startAddr & ~1;
        auto knownEnd = start;
        uint16_t *p;
        for(p = start; p + 2 <= endOfWorld && p < start + 0x400; p++, addr += 2) {
            uint32_t jumpTarget = 0;
            if((p[0] & 0xf000) == 0xd000) { // B1
                jumpTarget = signExtend(p[0] & 0xff, 8);
                p[0] = 0x42;
            } else if((p[0] & 0xf800) == 0xe000) { // B2
                jumpTarget = signExtend(p[0] & 0x7ff, 11);
                p[0] = 0x43;
            } else if((p[0] & 0xf800) == 0xf000 && ((p[1] & 0xd000) == 0x8000) && ((p[0] & 0x380) >> 7) != 7) { // B3
                jumpTarget = signExtend(((p[0] & 0x400) << 9) | ((p[1] & 0x800) << 7) | ((p[1] & 0x2000) << 4) | ((p[0] & 0x3f) << 11) | (p[1] & 0x7ff), 20);
                p[0] = p[1] = 0x44;
            } else if((p[0] & 0xf500) == 0xb100) { // CB[N]Z
                jumpTarget = ((p[0] & 0x200) >> 4) | ((p[0] & 0xf8) >> 3);
            } else if((p[0] & 0xf800) == 0x4800) { // LDR literal
                auto target = (uint32_t *) (p + ((addr & 2) ? 1 : 2) + 2*(p[0] & 0xff));
                if(target < (uint32_t *) endOfWorld) {
                    refs.push_back(make_pair(make_pair(addr, *target), false));
                }
                p[0] = 0x45;
            } else if((p[0] & 0xff7f) == 0xf85f) { // LDR literal 2
                auto target = (uint32_t *) ((uint8_t *) p + ((addr & 2) ? 2 : 4) + (p[1] & 0xfff));
                if(target < (uint32_t *) endOfWorld) {
                    refs.push_back(make_pair(make_pair(addr, *target), false));
                }
                p[0] = p[1] = 0x46;
            } else if((p[0] & 0xf800) == 0xf000 && (p[1] & 0xc000) == 0xc000) { // BL(X)
                // gross
                auto S = ((p[0] & 0x400) >> 10), J1 = (p[1] & 0x2000) >> 13, J2 = (p[1] & 0x800) >> 11;
                auto I1 = ~(J1 ^ S) & 1, I2 = ~(J2 ^ S) & 1;
                auto diff = ((p[0] & 0x400) >> 14) | (I1 << 23) | (I2 << 22) | ((p[0] & 0x3ff) << 12) | ((p[1] & 0x7ff) << 1);
                diff = signExtend(diff, 24);
                if(diff & 0x800000) diff |= 0xff000000;
                auto target = addr + diff + 4;  
                if(p[1] & 0x1000) { // BL
                    target |= 1;
                } else { // BLX
                    target &= ~2;
                }
                refs.push_back(make_pair(make_pair(addr, target), true));

                p[0] = p[1] = 0x46;
            } else if(
                (type == THUMB_FUNC && p[0] == (0xbd00 | (start[0] & 0xff))) ||
                (type == THUMB_VARARGS_FUNC && (p[0] & 0xb000) == 0xb000 && p[1] == 0x4770)) { // end of function
                jumpTarget = UINT32_MAX;
            }

            /*if(startAddr == 0x800632bd) {
                fprintf(stderr, "%x -> %x\n", startAddr + 2*(p - start), jumpTarget);
            }*/

            if(jumpTarget) {
                if(jumpTarget != UINT32_MAX) {
                    auto newEnd = p + 2 + jumpTarget;
                    if(newEnd < endOfWorld && newEnd > knownEnd) knownEnd = newEnd;
                }
                if(p >= knownEnd) break;
            }
            if(((p[0] >> 13) & 0b111) == 0b111 && ((p[0] >> 11) & 0b11) != 0b00) {
                // 32-bit
                p++, addr += 2;
            }
        }
        end = p;
    }

    void setHash() {
        auto hstart = start;
        auto hend = end;
        switch(hashMode) {
        case BEGINNING_HASH:
            hstart = start;
            hend = hstart + 7;
            break;
        case ENDING_HASH:
            hend = end;
            hstart = hend - 7;
            break;
        }

        if(hstart < start) hstart = start;
        if(hend > end) hend = end;

        for(auto p = hstart; p + 1 <= hend; p++) {
            hash += *p;
        }
    }

    double predict(const Function *other) const {
        size_t myLength = end - start, hisLength = other->end - other->start;
        if(type != other->type) {
            return 0.0;
        }
        if(type == INCOMPLETE_FUNC) {
            return 0.5;
        }
        if(myLength <= 7 && hisLength <= 7) {
            return (myLength == hisLength && !memcmp(start, other->start, myLength)) ? 1.0 : 0.0;
        }
        double failed = 0;
        for(auto p = start; p < end;) {
            size_t bestBitLength = 1;
            for(auto q = other->start; q < other->end; q++) {
                size_t i = 0;
                for(i = 0; q + i < other->end && p + i < end; i++) {
                    if(q[i] != p[i]) break;
                }
                if(i > bestBitLength) {
                    bestBitLength = i;
                }
            }
            if(bestBitLength < 5) failed += bestBitLength;
                
            p += bestBitLength;
        }
        return 1.0 - (failed / myLength);
    }
};

struct Edge {
    Function *source, *dest;
    uint32_t hash;
    Edge(Function *source, Function *dest)
    : source(source), dest(dest) {
        source->forward.push_back(this);
        dest->backward.push_back(this);
    }
    inline void setHash() {
        hash = source->hash ^ ((dest->hash >> 16) | (dest->hash << 16));
    }
};


struct Binary {
    struct binary binary;
    const char *filename;
    unordered_map<addr_t, Function *> funcs;
    unordered_map<uint32_t, vector<Function *>> funcsByHash;
    map<string, Function *> funcsByName;
    vector<Function *> funcsList;
    unordered_map<uint32_t, vector<Edge *>> edgesByHash;
    
    unordered_map<addr_t, const char *> reverseSymbols;

    Binary(const char *filename)
    : filename(filename) {
        b_init(&binary);
        b_load_macho(&binary, filename);
        
        doFuncs();
        doSymbols();
    }

    void doSymbols() {
        for(uint32_t i = 0; i < binary.mach->nsyms; i++) {
            struct nlist *nl = binary.mach->symtab + i;
            if(nl->n_value && (uint32_t) nl->n_un.n_strx < binary.mach->strsize) {
                auto it = funcs.find(nl->n_value | ((nl->n_desc & N_ARM_THUMB_DEF) ? 1 : 0));
                if(it != funcs.end()) {
                    setFuncName(it->second, binary.mach->strtab + nl->n_un.n_strx);
                }
            }
        }
    }

    void setFuncName(Function *func, const char *name) {
        // not quite right
        if(func->name) {
            auto it = funcsByName.find(func->name);
            if(it != funcsByName.end() && it->second == func) funcsByName.erase(it);
        }

        func->name = name;

        if(name) funcsByName[name] = func;
    }

    Function *addFunc(uint16_t *start, uint16_t *end, addr_t addr, int type) {
        Function *&func = funcs[addr];
        if(!func) {
            func = new Function(start, end, (uint16_t *) (binary.valid_range.start + binary.valid_range.size), addr, reverseSymbols[addr], type);
            funcsList.push_back(func);
        }
        return func;
    }

    void cut(const set<uint32_t>& cutPoints, bool explain) {
        uint32_t x = 0;
        for(auto func : funcsList) {
            uint32_t hash = func->hash;
            func->hash ^= x;
            //func->hash = x;
            //printf("%08x: %x -> %x\n", func->startAddr, hash, func->hash);
            if(cutPoints.find(hash) != cutPoints.end()) {
                if(explain) printf("CUT: hash %x from %x\n", hash, func->startAddr);
                x = (hash << 2);
            }
        }
    }

    void doFuncs() {
        auto range = b_macho_segrange(&binary, "__TEXT");
        auto pr = rangeconv(range, MUST_FIND);

        auto start = (uint16_t *) pr.start, end = start + pr.size/2;
        auto addr = range.start;
        for(uint16_t *p = start; p + 4 <= end; p++, addr += 2) {
            if((p[0] == 0xb40f || p[0] == 0xb40c) && (p[1] & 0xff00) == 0xb500 && (p[2] & 0xff00) == 0xaf00) {
                addFunc(p, NULL, addr | 1, THUMB_VARARGS_FUNC);
            } else if((p[0] & 0xff00) == 0xb500 && (p[1] & 0xff00) == 0xaf00) {
                addFunc(p, NULL, addr | 1, THUMB_FUNC);
            } else if((p[0] & 0xf83f) == 0x6800 && p[1] == 0x4770) {
                addFunc(p, p + 2, addr | 1, THUMB_ACCESSOR_FUNC);
            }
        }

        for(auto func : funcsList) {
            for(auto p : func->refs) {
                auto b = p.first.second;
                auto executable = p.second;
                if(b_in_vmrange(&binary, b)) {
                    Function *&func2 = funcs[b];
                    if(!func2) {
                        prange_t pr = rangeconv((range_t) {&binary, b, 4}, 0);
                        if(!pr.start || !executable) {
                        //value = *((uint32_t *) pr.start), 
                        //(/* hack */ true || b_in_vmrange(&binary, value)))) {
                            // quick guess
                            pr.size = 0;
                        }
                        func2 = addFunc((uint16_t *) pr.start, (uint16_t *) (pr.start + pr.size), b, INCOMPLETE_FUNC);
                    }
                    new Edge(func, func2);
                }
            }
        }
        
        for(auto func : funcsList) {
            #define X(direction, port) \
            if(hashMode == FULL_HASH && false) { \
                for(auto edge : func->direction) { \
                    func->hash ^= ~(edge->port->hash); \
                } \
            } else { \
                if(func->direction.size() == 1) { \
                    func->hash += ~(*func->direction.begin())->port->hash; \
                } \
            }
            X(forward, dest)
            X(backward, source)
            #undef X
        }

        sort(funcsList.begin(), funcsList.end(), [](Function *const& a, Function *const& b) { return a->startAddr < b->startAddr; });
    }

    void doHashes() {
        if(edgesByHash.size()) return;
        for(auto func : funcsList) {
            funcsByHash[func->hash].push_back(func);
            for(auto edge : func->forward) {
                edge->setHash();
                edgesByHash[edge->hash].push_back(edge);
            }
        }
    }

    unordered_map<uint32_t, list<Function *>> getFuncsByHash() {
        typeof(getFuncsByHash()) result;
        for(auto func : funcsList) {
            result[func->hash].push_back(func);
        }
        return result;
    }

    void identifyVtables(bool explain) {
        doHashes();

        auto constructor = funcsByName["__ZN11OSMetaClassC2EPKcPKS_j"];
        assert(constructor);
        unordered_map<addr_t, const char *> metaClasses;
        for(auto edge : constructor->backward) {
            auto nameAddr = edge->source->refs.begin()->first.second;
            if(!nameAddr) continue;
            // xxx
            auto className = (const char *) rangeconv((range_t) {&binary, nameAddr, 128}, 0).start;
            if(!className) continue;
            if(edge->source->backward.size() != 1) continue;
            auto mcInstantiator = (*edge->source->backward.begin())->source;
            addr_t metaClass;
            auto it = mcInstantiator->refs.begin();
            for(it++; it != mcInstantiator->refs.end(); it++) {
                if(it->first.second == edge->source->startAddr) {
                    auto it2 = it;
                    it2--;
                    metaClass = it2->first.second;
                    goto ok;
                }
            }
            continue;
            ok:
            if(explain) printf("ok %s\n", className);
            metaClasses[metaClass] = className;
        }

        auto constructed = funcsByName["__ZNK11OSMetaClass19instanceConstructedEv"];
        for(auto edge : constructed->backward) {
            if(edge->source->refs.size() == 4) {
                auto it = edge->source->refs.begin();
                auto metaClass = it->first.second;
                it++; it++;
                auto vtable = it->first.second - 8;
                auto className = metaClasses[metaClass];
                if(!className) continue;

                if(explain) printf("%x: %s\n", metaClass, className);
                    
                auto func = addFunc(NULL, NULL, vtable, INCOMPLETE_FUNC); 
                char funcName[128];
                snprintf(funcName, sizeof(funcName), "__ZTV%zd%s", strlen(className), className);
                setFuncName(func, funcName);
            }
        }
                
       //for(auto edge : func->backward) {
    }

    void injectSymbols(const char *output) {
        // need a fresh copy that's not normalized 
        struct binary binary;
        b_init(&binary);
        b_load_macho(&binary, filename);

        char *str = binary.mach->strtab + 4;
        struct nlist *nl = binary.mach->symtab;
        for(auto p : funcsByName) {
            if(nl - binary.mach->symtab >= binary.mach->nsyms) {
                fprintf(stderr, "symbol overflow\n");
                break;
            }
            memset(nl, 0, sizeof(*nl));
            nl->n_un.n_strx = str - binary.mach->strtab;
            nl->n_value = p.second->startAddr & ~1;
            if(p.second->startAddr & 1) {
                nl->n_desc |= N_ARM_THUMB_DEF;
            }
            
            auto size = p.first.size();
            if(str + size >= binary.mach->strtab + binary.mach->strsize) {
                fprintf(stderr, "string overflow at %s\n", p.first.c_str());
                abort();
            }
            strlcpy(str, p.first.data(), size + 1);
            str += size + 1;
            nl++;
        }

        CMD_ITERATE(binary.mach->hdr, cmd) {
            if(cmd->cmd == LC_SYMTAB) {
                auto s = (struct symtab_command *) cmd;
                s->nsyms = nl - binary.mach->symtab;
            } else if(cmd->cmd == LC_DYSYMTAB) {
                auto d = (struct dysymtab_command *) cmd;
                d->iextdefsym = 0;
                d->nextdefsym = nl - binary.mach->symtab;
            }
        }

        
        b_macho_store(&binary, output);
    }
};

static void doCutPoints(Binary *ba, Binary *bb, bool explain = false) {
    auto funcsByHashA = ba->getFuncsByHash(), funcsByHashB = bb->getFuncsByHash();
    
    set<uint32_t> cutPoints;
    for(auto p : funcsByHashA) {
        if(p.second.size() == 1 &&
           funcsByHashB[p.first].size() == 1) {
            cutPoints.insert(p.first);
        }
    }

    if(explain) {
        // verify (by hand) that cut points are actually in the same order between the binaries
        auto it = ba->funcsList.begin(), it2 = bb->funcsList.begin();
        while(it != ba->funcsList.end() && it2 != bb->funcsList.end()) {
            while(cutPoints.find((*it)->hash) == cutPoints.end()) if(++it == ba->funcsList.end()) goto done;
            while(cutPoints.find((*it2)->hash) == cutPoints.end()) if(++it2 == bb->funcsList.end()) goto done;
            if((*it)->hash != (*it2)->hash) printf("XXX ");
            printf("%08x:%08x %x:%x\n", (*it)->startAddr, (*it2)->startAddr, (*it)->hash, (*it2)->hash);
            it++; it2++;
        }
        done:;
    }

    ba->cut(cutPoints, explain);
    bb->cut(cutPoints, explain);

}

static list<pair<Function *, Function *>> doMatch(Binary *ba, Binary *bb, bool explain = false) {
    doCutPoints(ba, bb);
    ba->doHashes();
    bb->doHashes();

    // This is not the most efficient thing
    unordered_map<Function *, unordered_map<Function *, double>> xs;
    unordered_map<Edge *, unordered_map<Edge *, double>> ys;

    for(auto a : ba->funcsList) {
        for(auto b : bb->funcsByHash[a->hash]) {
            double val;
            auto forward = a->predict(b), backward = b->predict(a);
            val = (forward + backward) / 2;
            xs[a][b] = val;
        }
    }

    struct MetaEdge {
        double *source;
        double weight;
    };

    struct MetaVertex {
        double *dest;
        MetaEdge *edges;
    };
    
    vector<MetaVertex> mvs;

    fprintf(stderr, "5.1\n");
    // 5.1
    for(auto group : ba->edgesByHash) {
        for(auto edge1 : group.second) {
            for(auto edge2 : bb->edgesByHash[edge1->hash]) {
                MetaVertex mv;
                mv.dest = &ys[edge1][edge2];
                mv.edges = new MetaEdge[3];
                mv.edges[0] = (MetaEdge) {&xs[edge1->source][edge2->source], 1};
                mv.edges[1] = (MetaEdge) {&xs[edge1->dest][edge2->dest], 1};
                mv.edges[2] = (MetaEdge) {NULL, 0};
                mvs.push_back(mv);
            }
        }
    }

    fprintf(stderr, "5.2\n");
    // 5.2, tweaked to account for order
    // not perfect 
    // but that needs be divided by something
    // oh, and we can't completely discard the original xs value because some functions neither call or are called by anyone we know; we still can use matching
    for(auto a : ba->funcsList) {
        //printf("%d %x\n", (int) bb->funcsByHash[a->hash].size(), a->startAddr);
        for(auto b : bb->funcsByHash[a->hash]) {
            //printf("welp\n");
            MetaVertex mv;
            mv.dest = &xs[a][b];
            MetaEdge *ptr = mv.edges = new MetaEdge[a->forward.size() * b->forward.size() + a->backward.size() * b->backward.size() + 2];
            #define X(direction) \
            if(a->direction.size() == b->direction.size()) { \
                for(auto it = a->direction.begin(), it2 = b->direction.begin(); \
                         it != a->direction.end(); \
                         it++, it2++) { \
                    *ptr++ = (MetaEdge) {&ys[*it][*it2], 1}; \
                } \
            } else { \
                double multiplier = 1.0 / (a->direction.size() + b->direction.size()); /* not a mistake */ \
                for(auto ar : a->direction) { \
                    for(auto br : b->direction) { \
                        *ptr++ = (MetaEdge) {&ys[ar][br], multiplier}; \
                    } \
                } \
            }
            X(forward)
            X(backward)
            #undef X
            *ptr++ = (MetaEdge) {mv.dest, 0.1};
            *ptr++ = (MetaEdge) {NULL, 0};
            mvs.push_back(mv);
        }
    }

    size_t size = mvs.size();
    MetaVertex *mvp = &mvs[0];

    for(int iteration = 0; iteration < 6; iteration++) {
        fprintf(stderr, "%d (%zd to go)\n", iteration, size);
        if(0) {
            // debug
            printf("--\n");
            #define F(addr) \
            for(auto p : xs[ba->funcs[addr]]) { \
                printf("%x=%x %f\n", addr, p.first->startAddr, p.second); \
            } \
            if(1) for(auto e : ba->funcs[addr]->backward) { \
                for(auto p : ys[e]) { \
                    printf("%x->%x=%x->%x %f\n", e->source->startAddr, e->dest->startAddr, p.first->source->startAddr, p.first->dest->startAddr, p.second); \
                } \
            }
            F(0x80063890)
        }
        MetaVertex *mymvp = mvp;
        for(size_t i = 0; i < size; i++, mymvp++) {
            MetaEdge *edge = mymvp->edges;
            double result = 0;
            while(edge->source) {
                result += edge->weight * *edge->source;
                edge++;
            }
            *mymvp->dest = result;
        }
    }

    list<pair<Function *, Function *>> result;

    for(auto p : xs) {
        Function *maxFunction = NULL;
        if(explain) printf("%08x (%s):\n", p.first->startAddr, p.first->name);
        double maxValue = -1;
        for(auto p2 : p.second) {
            if(explain) printf("  %x=%f (predict:%f,%f)\n", p2.first->startAddr, p2.second, p.first->predict(p2.first), p2.first->predict(p.first));
            if(p2.second > maxValue) {
                maxValue = p2.second;
                maxFunction = p2.first;
            }
        }
        if(explain) printf("Max: %x\n\n", maxFunction ? maxFunction->startAddr : 0);
        if(maxFunction) {
            result.push_back(make_pair(p.first, maxFunction));
        }
    }

    return result;
}

static list<pair<Function *, Function *>> doMatchTrivially(Binary *ba, Binary *bb) {
    if(ba->funcsList.size() != bb->funcsList.size()) {
        fprintf(stderr, "funcs list not the same size: %d/%d\n", (int) ba->funcsList.size(), (int) bb->funcsList.size());
    }
    list<pair<Function *, Function *>> result;
    for(auto it = ba->funcsList.begin(), it2 = bb->funcsList.begin();
             it != ba->funcsList.end() && it2 != bb->funcsList.end();
             it++, it2++) {
        result.push_back(make_pair(*it, *it2));
    }
    return result;
}

int main(__unused int argc, char **argv) {
    argv++;
    Binary *ba = NULL;
    while(auto arg = *argv++)
    if(!strncmp(arg, "--", 2)) {
        string mode = arg;
        if(mode.find("--hash=") == 0) {
            string type = mode.substr(7);
            if(type == "beginning") hashMode = BEGINNING_HASH;
            else if(type == "ending") hashMode = ENDING_HASH;
            else if(type == "full") hashMode = FULL_HASH;
        } else if(mode == "--list") {
            printf("List of funcs:\n");
            bool refs = false;
            if(*argv && !strcmp(*argv, "--refs")) {
                refs = true;
                argv++;
            }
            for(auto func : ba->funcsList) {
                printf("%x-%x l=%ld h=%x n=%s f=%d b=%d t=%d\n", func->startAddr, (addr_t) (func->startAddr + 2*(func->end - func->start)), func->end - func->start, func->hash, func->name, (int) func->forward.size(), (int) func->backward.size(), func->type);
                if(refs) for(auto ref : func->refs) {
                    printf("  r:%x->%x (%s)\n", (int) ref.first.first, (int) ref.first.second, ref.second ? "(code)" : "(data)");
                }
            }
        } else if(mode == "--cut") {
            Binary bb(*argv++);
            bool explain = false;
            if(*argv && !strcmp(*argv, "--explain")) {
                explain = true;
                argv++;
            }
            doCutPoints(ba, &bb, explain);
        } else if(mode == "--byHash") {
            printf("List of funcs by hash:\n");
            ba->doHashes();

            for(auto p : ba->funcsByHash) {
                printf("%d - [%08x]:", (int) p.second.size(), p.first);
                for(auto func : p.second) {
                    printf("  %x", func->startAddr);
                }
                printf("\n");
            }

        } else if(mode == "--compare") {
            Binary bb(*argv++);
            for(auto p : ba->reverseSymbols) {
                auto myAddr = p.first, otherAddr = b_sym(&bb.binary, p.second, TO_EXECUTE);
                auto first = ba->funcs[myAddr], second = bb.funcs[otherAddr];
                if(first && second) {
                    double forward = first->predict(second), backward = second->predict(first);
                    printf("%.32s (%08x/%08x): %f\n", p.second, myAddr, otherAddr, (forward + backward) / 2);
                }
            }
        } else if(mode == "--matchF" || mode == "--matchB" || mode == "--trivial") {
            Binary bb(*argv++);
            bool explain = false;
            if(*argv && !strcmp(*argv, "--explain")) {
                explain = true;
                argv++;
            }
            list<pair<Function *, Function *>> result;
            if(mode == "--matchF") {
                result = doMatch(ba, &bb, explain);
            } else if(mode == "--matchB") {
                for(auto p : doMatch(&bb, ba, explain)) result.push_back(make_pair(p.second, p.first));
            } else if(mode == "--trivial") {
                result = doMatchTrivially(ba, &bb);
            }

            if(*argv && !strcmp(*argv, "--audit")) {
                for(auto p : result) {
                    const char *trueName = ba->reverseSymbols[p.first->startAddr];
                    const char *name = bb.reverseSymbols[p.second->startAddr];
                    if(name && trueName && strcmp(name, trueName)) {
                        printf("Wrong: %x=%x (%s = %s)\n", p.first->startAddr, p.second->startAddr, trueName, name);
                    }
                }
                argv++;
            } else if(*argv && !strcmp(*argv, "--show")) {
                for(auto p : result) {
                    auto func1 = p.first, func2 = p.second;
                    printf("%08x/%08x %f/%f %s/%s\n", func1->startAddr, func2->startAddr, func1->predict(func2), func2->predict(func1), func1->name, func2->name);
                }
                argv++;
            }

            for(auto p : result) {
                ba->setFuncName(p.first, p.second->name);
            }
        } else if(mode == "--clear") {
            // HACK
            for(auto func : ba->funcsList) {
                if(func->name && strcmp(func->name, "__ZN11OSMetaClassC2EPKcPKS_j") && strcmp(func->name, "__ZNK11OSMetaClass19instanceConstructedEv"))
                    ba->setFuncName(func, NULL);
            }
        } else if(mode == "--vt") {
            bool explain = false;
            if(*argv && !strcmp(*argv, "--explain")) {
                explain = true;
                argv++;
            }
            ba->identifyVtables(explain);
        } else if(mode == "--manual") {
            const char *name = *argv++;
            string mode = *argv++;
            addr_t addr;
            auto range = b_macho_segrange(&ba->binary, "__TEXT");
            if(mode == "strref") {
                addr = find_bof(range, find_int32(range, find_string(range, *argv++, 1, MUST_FIND), MUST_FIND), 2);
            } else if(mode == "inline-strref") {
                addr = find_bof(range, find_string(range, *argv++, 1, MUST_FIND), 2);
            } else if(mode == "pattern") {
                addr = find_data(range, *argv++, 0, MUST_FIND);
            } else {
                fprintf(stderr, "? %s\n", mode.c_str());
                abort();
            }
            auto func = ba->funcs[addr];
            if(!func) {
                fprintf(stderr, "not a Function: %x\n", addr);
                abort();
            }
            ba->setFuncName(func, name);
        } else {
            fprintf(stderr, "? %s\n", mode.c_str());
            abort();
        }
    } else if(!ba) {
        ba = new Binary(arg);
    } else {
        // write back
        ba->injectSymbols(arg);
    }

    return 0;
}
