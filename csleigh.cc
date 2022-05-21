//
// Minimal SLEIGH library C API, for disassembly and translation to P-code.
//
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include "sleigh/loadimage.hh"
#include "sleigh/sleigh.hh"
#include "csleigh.h"

// #define DEBUG
#ifdef DEBUG
#define LOG(fmt, ...) fprintf(stderr, "csleigh: " fmt "\n", ## __VA_ARGS__);
#else
#define LOG(fmt, ...) do {} while (0)
#endif

// https://gist.github.com/xymopen/352cbb55ddc2a767ed7c5999cfed4d31
template< class T, class M >
static inline constexpr ptrdiff_t offset_of( const M T::*member ) {
    return reinterpret_cast< ptrdiff_t >( &( reinterpret_cast< T* >( 0 )->*member ) );
}
template< class T, class M >
static inline constexpr T* owner_of( M *ptr, const M T::*member ) {
    return reinterpret_cast< T* >( reinterpret_cast< intptr_t >( ptr ) - offset_of( member ) );
}

void convertAddressToCType(const Address &in, LPX(Address) &out) {
    out.space = (LPX(AddrSpace)*)in.getSpace();
    out.offset = in.getOffset();
}

class SimpleLoadImage : public LoadImage
{
    uintb                m_baseaddr;
    int4                 m_length;
    const unsigned char *m_data;

public:
    SimpleLoadImage()
    : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data = NULL;
        m_length = 0;
    }

    void setData(uintb ad, const unsigned char *ptr,int4 sz)
    {
        m_baseaddr = ad;
        m_data = ptr;
        m_length = sz;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr)
    {
        LOG("Filling %d bytes at %lx", size, addr.getOffset());
        uintb start = addr.getOffset();
        uintb max = m_baseaddr + m_length - 1;

        //
        // When decoding an instruction, SLEIGH will attempt to pull in several
        // bytes at a time, starting at each instruction boundary.
        //
        // If the start address is outside of the defined range, bail out.
        // Otherwise, if we have some data to provide but cannot sastisfy the
        // entire request, fill the remainder of the buffer with zero.
        //
        if (start > max || start < m_baseaddr) {
            throw std::out_of_range("Attempting to lift outside buffer range");
        }

        for(int4 i = 0; i < size; i++) {
            uintb curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff>max)) {
                ptr[i] = 0;
                continue;
            }
            uintb diff = curoff - m_baseaddr;
            ptr[i] = m_data[(int4)diff];
        }
    }

    virtual string getArchType(void) const { return "myload"; }
    virtual void adjustVma(long adjust) { }
};


class PcodeEmitCacher : public PcodeEmit
{
public:
    vector<unique_ptr<LPX(Varnode)[]>> m_vars;
    vector<LPX(PcodeOp)>               m_ops;
    uintm                              m_uniq;

    PcodeEmitCacher()
    : m_uniq(0)
    {
    }

    void createVarnode(const VarnodeData *var, LPX(Varnode) &out)
    {
        assert(var->space != NULL);
        out.space = (LPX(AddrSpace)*)(var->space);
        out.offset = var->offset;
        out.size = var->size;
    }

    void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
              VarnodeData *vars, int4 isize)
    {
        assert(isize > 0);

        m_ops.emplace_back();
        LPX(PcodeOp) &op = m_ops.back();
        convertAddressToCType(addr, op.seq.pc);
        op.seq.uniq = m_uniq++;
        op.opcode = (LPX(OpCode))opc;

        int num_varnodes = isize;
        if (outvar) num_varnodes += 1;
        LPX(Varnode) *vna = new LPX(Varnode)[num_varnodes];

        int vni = 0;
        if (outvar) {
            createVarnode(outvar, vna[vni]);
            op.output = &vna[vni++];
        } else {
            op.output = NULL;
        }

        op.inputs_count = isize;
        op.inputs = &vna[vni];
        for (int4 i = 0; i < isize; i++) {
            createVarnode(&vars[i], vna[vni++]);
        }

        m_vars.emplace_back(vna);
    }
};


class AssemblyEmitCacher : public AssemblyEmit
{
public:
    Address  m_addr;
    string   m_mnem;
    string   m_body;

    void dump(const Address &addr, const string &mnem, const string &body)
    {
        m_addr = addr;
        m_mnem = mnem;
        m_body = body;
    };
};


class TranslationResult
{
public:
    LPX(TranslationResult)     m_res;
    string                     m_error_msg;
    vector<LPX(Translation)>   m_insns;
    vector<AssemblyEmitCacher> m_asms;
    vector<PcodeEmitCacher>    m_pcodes;

    TranslationResult()
    {
        LOG("Created result %p", this);
        m_res.error.type = LPX(ERROR_TYPE_NOERROR);
    }

    ~TranslationResult() {
        LOG("Destroying result %p", this);
    }

    void updateWithException(UnimplError &e, Address &addr)
    {
        m_res.error.type = LPX(ERROR_TYPE_UNIMPL);
        m_error_msg = e.explain;
        m_res.error.explain = m_error_msg.c_str();
        convertAddressToCType(addr, m_res.error.unimpl.address);
        m_res.error.unimpl.instruction_length = e.instruction_length;
    }

    void updateWithException(BadDataError &e, Address &addr)
    {
        m_res.error.type = LPX(ERROR_TYPE_BADDATA);
        m_error_msg = e.explain;
        m_res.error.explain = m_error_msg.c_str();
        convertAddressToCType(addr, m_res.error.baddata.address);
    }
};


class TranslationContext
{
public:
    SimpleLoadImage     m_loader;
    ContextInternal     m_context_internal;
    DocumentStorage     m_document_storage;
    Document           *m_document;
    Element            *m_tags;
    unique_ptr<Sleigh>  m_sleigh;
    string              m_register_name_cache;

    TranslationContext()
    {
        LOG("%p Context created", this);
    }

    ~TranslationContext()
    {
        LOG("%p Freeing context", this);
    }

    bool loadSlaFile(const char *path)
    {
        LOG("%p Loading slafile...", this);
        // FIXME: try/catch XmlError
        m_document = m_document_storage.openDocument(path);
        m_tags = m_document->getRoot();
        m_document_storage.registerTag(m_tags);

        LOG("Setting up translator");
        m_sleigh.reset(new Sleigh(&m_loader, &m_context_internal));
        m_sleigh->initialize(m_document_storage);

        return true;
    }

    LPX(TranslationResult) *translate(const unsigned char *bytes,
                                      unsigned int num_bytes,
                                      uintb address,
                                      unsigned int max_instructions,
                                      bool bb_terminating)
    {
        LOG("%p Translating bytes=%p, num_bytes=%d, address=%lx, "
            "max_instructions=%d",
            this, bytes, num_bytes, address, max_instructions);

        // Reset state
        m_sleigh->reset(&m_loader, &m_context_internal);
        m_sleigh->initialize(m_document_storage);
        m_loader.setData(address, bytes, num_bytes);

        TranslationResult *res = new TranslationResult();
        int4 offset = 0;
        bool end_bb = false;

        // Translate instructions
        while (!end_bb && (offset < num_bytes) && (!max_instructions ||
               (res->m_insns.size() < max_instructions))) {
            Address addr(m_sleigh->getDefaultCodeSpace(), address + offset);
            try {
                int4 ilen = m_sleigh->instructionLength(addr);

                res->m_asms.emplace_back();
                m_sleigh->printAssembly(res->m_asms.back(), addr);

                res->m_pcodes.emplace_back();
                m_sleigh->oneInstruction(res->m_pcodes.back(), addr);

                res->m_insns.emplace_back();
                LPX(Translation) &insn = res->m_insns.back();
                convertAddressToCType(addr, insn.address);
                insn.length = ilen;

                offset += ilen;

                if (bb_terminating) {
                    for (auto op : res->m_pcodes.back().m_ops) {
                        if (op.opcode == OP(BRANCH) ||
                            op.opcode == OP(CBRANCH) ||
                            op.opcode == OP(BRANCHIND) ||
                            op.opcode == OP(RETURN) ||
                            op.opcode == OP(CALL) ||
                            op.opcode == OP(CALLIND)) {
                            end_bb = true;
                            break;
                        }
                    }
                }
            } catch (UnimplError &e) {
                res->updateWithException(e, addr);
                break;
            } catch (BadDataError &e) {
                res->updateWithException(e, addr);
                break;
            }
        }

        // Serialize
        for (int i = 0; i < res->m_insns.size(); i++) {
            res->m_insns[i].asm_mnem = res->m_asms[i].m_mnem.c_str();
            res->m_insns[i].asm_body = res->m_asms[i].m_body.c_str();
            res->m_insns[i].ops = &res->m_pcodes[i].m_ops[0];
            res->m_insns[i].ops_count = res->m_pcodes[i].m_ops.size();
        }

        res->m_res.instructions_count = res->m_insns.size();
        if (res->m_res.instructions_count) {
            res->m_res.instructions = &res->m_insns[0];
        }

        return &res->m_res;
    }

    const char *Sleigh_getRegisterName(AddrSpace* as, uintb off, int4 size)
    {
        m_register_name_cache = m_sleigh->getRegisterName(as, off, size);
        return m_register_name_cache.c_str();
    }

    const LPX(Varnode) Sleigh_getRegister(const char* name)
    {
        const VarnodeData& varnode = m_sleigh->getRegister(std::string(name));
        LPX(Varnode) res = {
            .space = varnode.space,
            .offset = varnode.offset,
            .size = varnode.size
        };
        return res;
    }
};


//------------------------------------------------------------------------------
// C API
//------------------------------------------------------------------------------

LPX(Context) LPX(createContext)(const char *slafile)
{
    TranslationContext *ctx = new TranslationContext();
    if (!ctx->loadSlaFile(slafile)) {
        delete ctx;
        ctx = NULL;
    }
    return (LPX(Context))(ctx);
}

void LPX(destroyContext)(LPX(Context) c)
{
    delete (TranslationContext *)c;
}

LPX(TranslationResult) *LPX(translate)(LPX(Context) c,
                                       const unsigned char *bytes,
                                       unsigned int num_bytes,
                                       uintb address,
                                       unsigned int max_instructions,
                                       bool bb_terminating)
{
    return ((TranslationContext *)c)->translate(bytes, num_bytes, address,
                                                max_instructions,
                                                bb_terminating);
}

void LPX(freeResult)(LPX(TranslationResult) *r)
{
    if (r) delete owner_of(r, &TranslationResult::m_res);
}

void LPX(setVariableDefault)(LPX(Context) c, const char *name, uintm val)
{
    ((TranslationContext *)c)->m_context_internal.setVariableDefault(name, val);
}

int LPX(Addr_isConstant)(LPX(Address) *a)
{
    return Address((AddrSpace *)(a->space), a->offset).isConstant();
}

LPX(AddrSpace) LPX(Addr_getSpaceFromConst)(LPX(Address) *a)
{
    AddrSpace *space = Address::getSpaceFromConst(
        Address((AddrSpace *)(a->space), a->offset));
    return (LPX(AddrSpace))space;
}

const char *LPX(AddrSpace_getName)(LPX(AddrSpace) as)
{
    return ((AddrSpace *)as)->getName().c_str();
}

const int4 LPX(AddrSpace_getId)(LPX(AddrSpace) as)
{
    return ((AddrSpace *)as)->getIndex();
}

const char *LPX(Sleigh_getRegisterName)(LPX(Context) c, LPX(AddrSpace) as,
                                        uintb off, int4 size)
{
    return ((TranslationContext *)c)->Sleigh_getRegisterName(
        (AddrSpace *)as, off, size);
}

int LPX(Sleigh_getRegister)(LPX(Context) c, const char* name, LPX(Register)* o_reg)
{
    LPX(Varnode) varnode;
    try {
        varnode = ((TranslationContext *)c)->Sleigh_getRegister(name);
    } catch (const SleighError& e) {
        return 0;
    }

    memset(o_reg, 0, sizeof(LPX(Register)));
    strncpy(o_reg->name, name, sizeof(o_reg->name)-1);
    o_reg->varnode = varnode;
    return 1;
}

const LPX(AddrSpace) LPX(Sleigh_getDefaultCodeSpace)(LPX(Context) c)
{
    AddrSpace *space =
        ((TranslationContext *)c)->m_sleigh->getDefaultCodeSpace();
    return (LPX(AddrSpace))space;
}

const LPX(AddrSpace) LPX(Sleigh_getDefaultDataSpace)(LPX(Context) c)
{
    AddrSpace *space =
        ((TranslationContext *)c)->m_sleigh->getDefaultDataSpace();
    return (LPX(AddrSpace))space;
}

const LPX(AddrSpace) LPX(Sleigh_getConstantSpace)(LPX(Context) c)
{
    AddrSpace *space =
        ((TranslationContext *)c)->m_sleigh->getConstantSpace();
    return (LPX(AddrSpace))space;
}

const LPX(AddrSpace) LPX(Sleigh_getUniqueSpace)(LPX(Context) c)
{
    AddrSpace *space =
        ((TranslationContext *)c)->m_sleigh->getUniqueSpace();
    return (LPX(AddrSpace))space;
}

const LPX(AddrSpace) LPX(Sleigh_getSpaceByName)(LPX(Context) c, const char* name)
{
    AddrSpace *space =
        ((TranslationContext *)c)->m_sleigh->getSpaceByName(std::string(name));
    return (LPX(AddrSpace))space;
}

int LPX(Sleigh_getFloatFormats)(LPX(Context) c, FloatFormat* const** o_float_formats, size_t* o_size)
{
    ((TranslationContext *)c)->m_sleigh->setDefaultFloatFormats();

    std::vector<const FloatFormat*> v;
    for (int i=0; i<32; ++i) {
        const FloatFormat* ff = ((TranslationContext *)c)->m_sleigh->getFloatFormat(i);
        if (ff)
            v.push_back(ff);
    }

    FloatFormat** res =
        (FloatFormat**)malloc(sizeof(const FloatFormat*) * v.size());

    for (uint64_t i = 0; i < v.size(); ++i)
        res[i] = (FloatFormat*)v.at(i);

    *o_size = v.size();
    *o_float_formats = (FloatFormat* const*)res;
    return 1;
}

int LPX(Sleigh_getAllRegisters)(LPX(Context) c, LPX(Register)** o_regs, size_t* o_size)
{
    map<VarnodeData, string> regmap;
    ((TranslationContext *)c)->m_sleigh->getAllRegisters(regmap);

    LPX(Register)* regs = (LPX(Register)*)calloc(
        sizeof(LPX(Register)), regmap.size());

    int i = 0;
    for (const auto& [varnode, name] : regmap) {
        LPX(Varnode) v = {
            .offset = varnode.offset,
            .size   = varnode.size,
            .space  = (LPX(AddrSpace))varnode.space
        };
        strncpy(
            regs[i].name,
            name.c_str(),
            sizeof(regs[i].name) - 1UL);
        regs[i].varnode = v;
        i++;
    }

    *o_size = regmap.size();
    *o_regs = regs;
    return 1;
}

const char* LPX(OpCodeName)(LPX(OpCode) op) {
	switch (op) {
#define DEC_OP(oid, oname, odesc) case OP(oname): return #oname;
#define INV_OP(oid, oname, odesc)
OPS_X
#undef DEC_OP
#undef INV_OP
		default:
			break;
	}
	return "unknown";
};
