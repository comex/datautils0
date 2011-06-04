#include <data/mach-o/binary.h>
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

#define STRICT 1

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

// wtf
namespace std {
    template <typename A, typename B>
    struct hash<pair<A, B>> : public unary_function<pair<A, B>, size_t> {
        inline size_t operator()(const pair<A, B> p) const {
            hash<A> hA;
            hash<B> hB;
            return hA(p.first) ^ hB(p.second);
        }
    };
}

static uint32_t signExtend(uint32_t val, int bits) {
    if(val & (1 << (bits - 1))) {
        val |= ~((1 << bits) - 1);
    }
    return val;
}

enum {
    INCOMPLETE_FUNC,
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

    list<pair<addr_t, addr_t>> refs;

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
                p[0] = 0;
            } else if((p[0] & 0xf800) == 0xe000) { // B2
                jumpTarget = signExtend(p[0] & 0x7ff, 11);
                p[0] = 0;
            } else if((p[0] & 0xf800) == 0xf000 && ((p[1] & 0xd000) == 0x8000) && ((p[0] & 0x380) >> 7) != 7) { // B3
                jumpTarget = signExtend(((p[0] & 0x400) << 9) | ((p[1] & 0x800) << 7) | ((p[1] & 0x2000) << 4) | ((p[0] & 0x3f) << 11) | (p[1] & 0x7ff), 20);
                p[0] = p[1] = 0;
            } else if((p[0] & 0xf500) == 0xb100) { // CB[N]Z
                jumpTarget = ((p[0] & 0x200) >> 4) | ((p[0] & 0xf8) >> 3);
            } else if((p[0] & 0xf800) == 0x4800) { // LDR literal
                auto target = (uint32_t *) (p + ((addr & 2) ? 1 : 2) + 2*(p[0] & 0xff));
                if(target < (uint32_t *) endOfWorld) {
                    refs.push_back(make_pair(addr, *target));
                }
                p[0] = 0;
            } else if((p[0] & 0xff7f) == 0xf85f) { // LDR literal 2
                auto target = (uint32_t *) ((uint8_t *) p + ((addr & 2) ? 2 : 4) + (p[1] & 0xfff));
                if(target < (uint32_t *) endOfWorld) {
                    refs.push_back(make_pair(addr, *target));
                }
                p[0] = p[1] = 0;
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
                refs.push_back(make_pair(addr, target));

                p[0] = p[1] = 0;
            } else if(
                (type == THUMB_FUNC && p[0] == (0xbd00 | (start[0] & 0xff))) ||
                (type == THUMB_VARARGS_FUNC && p[0] == 0xb004 && p[1] == 0x4770)) { // end of function
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
        hash = 0;
        for(auto p = start; p + 1 <= end && (STRICT || p < start + 10); p++) {
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
        hash = source->hash ^ ((dest->hash >> 16) | (dest->hash << 16));
        source->forward.push_back(this);
        dest->backward.push_back(this);
    }
};


struct Binary {
    struct binary binary;
    const char *filename;
    unordered_map<addr_t, Function *> funcs;
    unordered_map<uint32_t, set<Function *>> funcsByHash;
    map<string, Function *> funcsByName;
    list<Function *> funcsList;
    unordered_map<uint32_t, list<Edge *>> edgesByHash;
    
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

    void setFuncHash(Function *func, uint32_t hash) {
        funcsByHash[func->hash].erase(func);
        funcsByHash[func->hash = hash].insert(func);
    }

    Function *addFunc(uint16_t *start, uint16_t *end, addr_t addr, int type) {
        Function *&func = funcs[addr];
        if(!func) {
            func = new Function(start, end, (uint16_t *) (binary.valid_range.start + binary.valid_range.size), addr, reverseSymbols[addr], type);
            funcsList.push_back(func);
        }
        return func;
    }

    void cut(const set<uint32_t>& cutPoints) {
        uint32_t x = 0;
        for(auto func : funcsList) {
            uint32_t hash = func->hash;
            setFuncHash(func, hash ^ x);
            if(cutPoints.find(hash) != cutPoints.end()) {
                //printf("CUT: %x\n", func->startAddr);
                x ^= (hash << 2);
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
            setFuncHash(func, func->hash);
            for(auto p : func->refs) {
                auto b = p.second;
                if(b_in_vmrange(&binary, b)) {
                    Function *&func2 = funcs[b];
                    if(!func2) {
                        prange_t pr = rangeconv((range_t) {&binary, b, 4}, 0);
                        if(!pr.start || b_in_vmrange(&binary, *((uint32_t *) pr.start))) {
                            // quick guess
                            pr.size = 0;
                        }
                        func2 = addFunc((uint16_t *) pr.start, (uint16_t *) (pr.start + pr.size), b, INCOMPLETE_FUNC);
                    }
                }
            }
        }
    }

    void doEdges() {
        if(edgesByHash.size()) return;
        for(auto func : funcsList) {
            for(auto p : func->refs) {
                auto it = funcs.find(p.second);
                if(it != funcs.end()) {
                    auto edge = new Edge(func, it->second);
                    edgesByHash[edge->hash].push_back(edge);
                }
            }
        }
    }
                

    void identifyVtables(bool explain) {
        doEdges();

        auto constructor = funcsByName["__ZN11OSMetaClassC2EPKcPKS_j"];
        assert(constructor);
        unordered_map<addr_t, const char *> metaClasses;
        for(auto edge : constructor->backward) {
            auto nameAddr = edge->source->refs.begin()->second;
            if(!nameAddr) continue;
            // xxx
            auto className = (const char *) rangeconv((range_t) {&binary, nameAddr, 128}, 0).start;
            if(!className) continue;
            if(edge->source->backward.size() != 1) continue;
            auto mcInstantiator = (*edge->source->backward.begin())->source;
            addr_t metaClass;
            auto it = mcInstantiator->refs.begin();
            for(it++; it != mcInstantiator->refs.end(); it++) {
                if(it->second == edge->source->startAddr) {
                    auto it2 = it;
                    it2--;
                    metaClass = it2->second;
                    goto ok;
                }
            }
            continue;
            ok:
            metaClasses[metaClass] = className;
        }

        auto constructed = funcsByName["__ZNK11OSMetaClass19instanceConstructedEv"];
        for(auto edge : constructed->backward) {
            if(edge->source->refs.size() == 4) {
                auto it = edge->source->refs.begin();
                auto metaClass = it->second;
                it++; it++;
                auto vtable = it->second - 8;
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

static void doCutPoints(Binary *ba, Binary *bb) {
    set<uint32_t> cutPoints;
    for(auto p : ba->funcsByHash) {
        if(p.second.size() == 1 &&
           bb->funcsByHash[p.first].size() == 1) {
            cutPoints.insert(p.first);
        }
    }
    ba->cut(cutPoints);
    bb->cut(cutPoints);
}

static list<pair<Function *, Function *>> doMatch(Binary *ba, Binary *bb) {
    doCutPoints(ba, bb);
    ba->doEdges();
    bb->doEdges();

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

    for(int iteration = 0; iteration < 6; iteration++) {
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
        // 5.1
        for(auto group : ba->edgesByHash) {
            for(auto edge1 : group.second) {
                for(auto edge2 : bb->edgesByHash[edge1->hash]) {
                    ys[edge1][edge2] = xs[edge1->source][edge2->source] + xs[edge1->dest][edge2->dest];
                }
            }
        }

        // 5.2, tweaked to account for order
        // not perfect 
        // but that needs be divided by something
        for(auto a : ba->funcsList) {
            for(auto b : bb->funcsByHash[a->hash]) {
                #define X(direction) \
                if(a->direction.size() == b->direction.size()) { \
                    for(auto it = a->direction.begin(), it2 = b->direction.begin(); \
                             it != a->direction.end(); \
                             it++, it2++) { \
                        result += ys[*it][*it2]; \
                    } \
                } else { \
                    double temp = 0; \
                    for(auto ar : a->direction) { \
                        for(auto br : b->direction) { \
                            temp += ys[ar][br]; \
                        } \
                    } \
                    result += temp / (a->direction.size() + b->direction.size()); /* not a mistake */ \
                }
                double result = 0;
                X(forward)
                X(backward)
                xs[a][b] = result;
            }
        }
    }

    list<pair<Function *, Function *>> result;

    for(auto p : xs) {
        Function *maxFunction = NULL;
        double maxValue = -1;
        for(auto p2 : p.second) {
            if(p2.second > maxValue) {
                maxValue = p2.second;
                maxFunction = p2.first;
            }
        }
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
    Binary ba(*argv++); 
    while(auto arg = *argv++)
    if(!strncmp(arg, "--", 2)) {
        string mode = arg;
        if(mode == "--list") {
            printf("List of funcs:\n");
            bool refs = false;
            if(*argv && !strcmp(*argv, "--refs")) {
                refs = true;
                argv++;
            }
            for(auto func : ba.funcsList) {
                printf("%x-%x l=%ld h=%x n=%s f=%d b=%d t=%d\n", func->startAddr, (addr_t) (func->startAddr + 2*(func->end - func->start)), func->end - func->start, func->hash, func->name, (int) func->forward.size(), (int) func->backward.size(), func->type);
                if(refs) for(auto ref : func->refs) {
                    printf("  r:%x->%x\n", (int) ref.first, (int) ref.second);
                }
            }
        } else if(mode == "--cut") {
            Binary bb(*argv++);
            doCutPoints(&ba, &bb);
        } else if(mode == "--byHash") {
            printf("List of funcs by hash:\n");

            for(auto p : ba.funcsByHash) {
                printf("%d - [%08x]:", (int) p.second.size(), p.first);
                for(auto func : p.second) {
                    printf("  %x", func->startAddr);
                }
                printf("\n");
            }

        } else if(mode == "--compare") {
            Binary bb(*argv++);
            for(auto p : ba.reverseSymbols) {
                auto myAddr = p.first, otherAddr = b_sym(&bb.binary, p.second, TO_EXECUTE);
                auto first = ba.funcs[myAddr], second = bb.funcs[otherAddr];
                if(first && second) {
                    double forward = first->predict(second), backward = second->predict(first);
                    printf("%.32s (%08x/%08x): %f\n", p.second, myAddr, otherAddr, (forward + backward) / 2);
                }
            }
        } else if(mode == "--matchF" || mode == "--matchB" || mode == "--trivial") {
            Binary bb(*argv++);
            list<pair<Function *, Function *>> result;
            if(mode == "--matchF") {
                result = doMatch(&ba, &bb);
            } else if(mode == "--matchB") {
                for(auto p : doMatch(&bb, &ba)) result.push_back(make_pair(p.second, p.first));
            } else if(mode == "--trivial") {
                result = doMatchTrivially(&ba, &bb);
            }

            if(!strcmp(*argv, "--audit")) {
                for(auto p : result) {
                    const char *trueName = ba.reverseSymbols[p.first->startAddr];
                    const char *name = bb.reverseSymbols[p.second->startAddr];
                    if(name && trueName && strcmp(name, trueName)) {
                        printf("Wrong: %x=%x (%s = %s)\n", p.first->startAddr, p.second->startAddr, trueName, name);
                    }
                }
                argv++;
            } else if(!strcmp(*argv, "--explain")) {
                for(auto p : result) {
                    auto func1 = p.first, func2 = p.second;
                    printf("%08x/%08x %f/%f %s/%s\n", func1->startAddr, func2->startAddr, func1->predict(func2), func2->predict(func1), func1->name, func2->name);
                }
                argv++;
            }

            for(auto p : result) {
                p.first->name = p.second->name;
            }
        } else if(mode == "--clear") {
            // HACK
            for(auto func : ba.funcsList) {
                if(func->name && strcmp(func->name, "__ZN11OSMetaClassC2EPKcPKS_j") && strcmp(func->name, "__ZNK11OSMetaClass19instanceConstructedEv"))
                    ba.setFuncName(func, NULL);
            }
        } else if(mode == "--vt") {
            bool explain = false;
            if(*argv && !strcmp(*argv, "--explain")) {
                explain = true;
                argv++;
            }
            ba.identifyVtables(explain);
        } else {
            fprintf(stderr, "? %s\n", mode.c_str());
            abort();
        }
    } else {
        // write back
        ba.injectSymbols(arg);
    }

    return 0;
}
