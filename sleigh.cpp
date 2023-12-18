#include "sleigh/sleigh.hh"
#include "sleigh/loadimage.hh"
#include "sleigh/xml.hh"

#include <sys/stat.h>
#include <sys/types.h>
#include <cassert>
#include <memory>

#include "sleigh.h"
#include "sleigh_float.h"

namespace
{

static std::string last_error = "";

template <class T, class M>
static inline constexpr ptrdiff_t offset_of(const M T::*member)
{
    return reinterpret_cast<ptrdiff_t>(&(reinterpret_cast<T*>(0)->*member));
}
template <class T, class M>
static inline constexpr T* owner_of(M* ptr, const M T::*member)
{
    return reinterpret_cast<T*>(reinterpret_cast<intptr_t>(ptr) -
                                offset_of(member));
}

static void convertAddressToCType(const ghidra::Address& in,
                                  sleigh_address_t&      out)
{
    out.space  = (sleigh_address_space_t*)in.getSpace();
    out.offset = in.getOffset();
}

static ghidra::Element* getChildByName(const ghidra::Element* el,
                                       std::string            name)
{
    for (ghidra::Element* child : el->getChildren()) {
        if (child->getName() == name)
            return child;
    }
    return nullptr;
}

class SimpleLoadImage : public ghidra::LoadImage
{
    uint8_t              m_baseaddr;
    uint32_t             m_length;
    const unsigned char* m_data;

  public:
    SimpleLoadImage() : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data     = NULL;
        m_length   = 0;
    }

    void setData(uint8_t ad, const unsigned char* ptr, int32_t sz)
    {
        m_baseaddr = ad;
        m_data     = ptr;
        m_length   = sz;
    }

    void loadFill(uint8_t* ptr, int32_t size, const ghidra::Address& addr)
    {
        uint8_t start = addr.getOffset();
        uint8_t max   = m_baseaddr + m_length - 1;

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

        for (int32_t i = 0; i < size; i++) {
            uint8_t curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff > max)) {
                ptr[i] = 0;
                continue;
            }
            uint8_t diff = curoff - m_baseaddr;
            ptr[i]       = m_data[(int32_t)diff];
        }
    }

    virtual std::string getArchType(void) const { return "myload"; }
    virtual void        adjustVma(long adjust) {}
};

class PcodeEmitCacher : public ghidra::PcodeEmit
{
  public:
    std::vector<std::unique_ptr<sleigh_varnode_t[]>> m_vars;
    std::vector<sleigh_pcodeop_t>                    m_ops;
    uint32_t                                         m_uniq;

    PcodeEmitCacher() : m_uniq(0) {}

    void createVarnode(const ghidra::VarnodeData* var, sleigh_varnode_t& out)
    {
        assert(var->space != NULL);
        out.space  = (sleigh_address_space_t*)var->space;
        out.offset = var->offset;
        out.size   = var->size;
    }

    virtual void dump(const ghidra::Address& addr, ghidra::OpCode opc,
                      ghidra::VarnodeData* outvar, ghidra::VarnodeData* vars,
                      int32_t isize)
    {
        assert(isize > 0);

        m_ops.emplace_back();
        sleigh_pcodeop_t& op = m_ops.back();
        convertAddressToCType(addr, op.seq.pc);
        op.seq.uniq = m_uniq++;
        op.opcode   = (sleigh_opcode_t)opc;

        int num_varnodes = isize;
        if (outvar)
            num_varnodes += 1;
        sleigh_varnode_t* vna = new sleigh_varnode_t[num_varnodes];

        int vni = 0;
        if (outvar) {
            createVarnode(outvar, vna[vni]);
            op.output = &vna[vni++];
        } else {
            op.output = NULL;
        }

        op.inputs_count = isize;
        op.inputs       = &vna[vni];
        for (uint32_t i = 0; i < isize; i++) {
            createVarnode(&vars[i], vna[vni++]);
        }

        m_vars.emplace_back(vna);
    }
};

class AssemblyEmitCacher : public ghidra::AssemblyEmit
{
  public:
    ghidra::Address m_addr;
    std::string     m_mnem;
    std::string     m_body;

    void dump(const ghidra::Address& addr, const std::string& mnem,
              const std::string& body)
    {
        m_addr = addr;
        m_mnem = mnem;
        m_body = body;
    };
};

class TranslationResult
{
  public:
    sleigh_translation_result_t       m_res;
    std::string                       m_error_msg;
    std::vector<sleigh_translation_t> m_insns;
    std::vector<AssemblyEmitCacher>   m_asms;
    std::vector<PcodeEmitCacher>      m_pcodes;

    TranslationResult()
    {
        m_res.error.type = SLEIGH_ERROR_TYPE_NOERROR;
        m_res.error.text = NULL;
    }
    ~TranslationResult() {}

    void updateWithException(ghidra::UnimplError& e, ghidra::Address& addr)
    {
        m_res.error.type = SLEIGH_ERROR_TYPE_UNIMPL;
        m_error_msg      = e.explain;
        m_res.error.text = m_error_msg.c_str();
    }

    void updateWithException(ghidra::BadDataError& e, ghidra::Address& addr)
    {
        m_res.error.type = SLEIGH_ERROR_TYPE_BADDATA;
        m_error_msg      = e.explain;
        m_res.error.text = m_error_msg.c_str();
    }
};

class TranslationContext
{
  public:
    SimpleLoadImage                 m_loader;
    ghidra::ContextInternal         m_context_internal;
    ghidra::DocumentStorage         m_document_storage;
    ghidra::Document*               m_document;
    ghidra::Element*                m_tags;
    std::unique_ptr<ghidra::Sleigh> m_sleigh;
    std::string                     m_register_name_cache;

    TranslationContext() : m_sleigh(nullptr) {}

    ~TranslationContext() {}

    bool loadSlaFile(const char* path)
    {
        ghidra::AttributeId::initialize();
        ghidra::ElementId::initialize();

        try {
            m_document = m_document_storage.openDocument(path);
            m_tags     = m_document->getRoot();
            m_document_storage.registerTag(m_tags);

            m_sleigh.reset(new ghidra::Sleigh(&m_loader, &m_context_internal));
            m_sleigh->initialize(m_document_storage);
        } catch (ghidra::LowlevelError e) {
            last_error = e.explain.c_str();
            return false;
        } catch (ghidra::DecoderError e) {
            last_error = e.explain.c_str();
            return false;
        }
        return true;
    }

    bool loadPspecFile(const char* path)
    {
        try {
            auto ds  = ghidra::DocumentStorage();
            auto doc = ds.openDocument(path);

            ghidra::Element* el;
            el = getChildByName(doc, "processor_spec");
            if (el == nullptr) {
                last_error = "unable to find \"processor_spec\" in spec file";
                return false;
            }
            el = getChildByName(el, "context_data");
            if (el == nullptr) {
                last_error = "unable to find \"context_data\" in spec file";
                return false;
            }
            el = getChildByName(el, "context_set");
            if (el == nullptr) {
                last_error = "unable to find \"context_set\" in spec file";
                return false;
            }
            for (ghidra::Element* el : el->getChildren()) {
                if (el->getName() != "set")
                    continue;

                std::string name = el->getAttributeValue("name");
                int         val  = std::stoi(el->getAttributeValue("val"));
                m_context_internal.setVariableDefault(name, val);
            }

        } catch (ghidra::DecoderError e) {
            last_error = e.explain.c_str();
            return false;
        } catch (std::invalid_argument e) {
            last_error = e.what();
            return false;
        } catch (std::out_of_range e) {
            last_error = e.what();
            return false;
        }
        return true;
    }

    sleigh_translation_result_t* translate(const unsigned char* bytes,
                                           unsigned int         num_bytes,
                                           uint64_t             address,
                                           unsigned int max_instructions,
                                           bool         bb_terminating)
    {
        // Reset state
        m_sleigh->reset(&m_loader, &m_context_internal);
        m_sleigh->initialize(m_document_storage);
        m_loader.setData(address, bytes, num_bytes);

        TranslationResult* res    = new TranslationResult();
        int32_t            offset = 0;
        bool               end_bb = false;

        // Translate instructions
        while (
            !end_bb && (offset < num_bytes) &&
            (!max_instructions || (res->m_insns.size() < max_instructions))) {
            ghidra::Address addr(m_sleigh->getDefaultCodeSpace(),
                                 address + offset);
            try {
                int32_t ilen = m_sleigh->instructionLength(addr);

                res->m_asms.emplace_back();
                m_sleigh->printAssembly(res->m_asms.back(), addr);

                res->m_pcodes.emplace_back();
                m_sleigh->oneInstruction(res->m_pcodes.back(), addr);

                res->m_insns.emplace_back();
                sleigh_translation_t& insn = res->m_insns.back();
                convertAddressToCType(addr, insn.address);
                insn.length = ilen;

                offset += ilen;

                if (bb_terminating) {
                    for (auto op : res->m_pcodes.back().m_ops) {
                        if (op.opcode == OP(BRANCH) ||
                            op.opcode == OP(CBRANCH) ||
                            op.opcode == OP(BRANCHIND) ||
                            op.opcode == OP(RETURN) || op.opcode == OP(CALL) ||
                            op.opcode == OP(CALLIND)) {
                            end_bb = true;
                            break;
                        }
                    }
                }
            } catch (ghidra::UnimplError& e) {
                res->updateWithException(e, addr);
                break;
            } catch (ghidra::BadDataError& e) {
                res->updateWithException(e, addr);
                break;
            }
        }

        // Serialize
        for (int i = 0; i < res->m_insns.size(); i++) {
            res->m_insns[i].asm_mnem  = res->m_asms[i].m_mnem.c_str();
            res->m_insns[i].asm_body  = res->m_asms[i].m_body.c_str();
            res->m_insns[i].ops       = &res->m_pcodes[i].m_ops[0];
            res->m_insns[i].ops_count = res->m_pcodes[i].m_ops.size();
        }

        res->m_res.instructions_count = res->m_insns.size();
        if (res->m_res.instructions_count) {
            res->m_res.instructions = &res->m_insns[0];
        }

        return &res->m_res;
    }

    const char* getRegisterName(ghidra::AddrSpace* as, uint64_t off,
                                int32_t size)
    {
        m_register_name_cache = m_sleigh->getRegisterName(as, off, size);
        return m_register_name_cache.c_str();
    }

    bool getRegister(const char* name, sleigh_varnode_t* res)
    {
        try {
            const ghidra::VarnodeData& varnode =
                m_sleigh->getRegister(std::string(name));
            res->space  = varnode.space;
            res->offset = varnode.offset;
            res->size   = varnode.size;
            return true;
        } catch (ghidra::SleighError e) {
        }
        return false;
    }
};

} // namespace

static bool directory_exists(const char* dir)
{
    if (dir == NULL)
        return false;

    struct stat info;
    if (stat(dir, &info) != 0)
        return false;
    if (info.st_mode & S_IFDIR)
        return true;
    return false;
}

// *** Public APIs ***

sleigh_ctx_t sleigh_create_context(sleigh_arch_t arch, sleigh_processor_t proc)
{
    const char* proc_dir = std::getenv("SLEIGH_PROCESSORS_DIR");
    if (proc_dir == NULL) {
        proc_dir = "./processors";
        if (!directory_exists(proc_dir))
            proc_dir = "./sleigh/processors";
        if (!directory_exists(proc_dir))
            proc_dir = "/usr/local/share/sleigh/processors";
    }
    if (!proc_dir) {
        last_error = "unable to find \"processors\" directory";
        return NULL;
    }

    std::string sla;
    std::string pspec;

    switch (arch) {
        case SLEIGH_ARCH_X86_64: {
            switch (proc) {
                case SLEIGH_PROC_X86_64: {
                    sla = std::string(proc_dir) +
                          std::string("/x86/data/languages/x86-64.sla");
                    pspec = std::string(proc_dir) +
                            std::string("/x86/data/languages/x86-64.pspec");
                } break;
                case SLEIGH_PROC_X86_16: {
                    sla = std::string(proc_dir) +
                          std::string("/x86/data/languages/x86-64.sla");
                    pspec = std::string(proc_dir) +
                            std::string("/x86/data/languages/x86-16.pspec");
                } break;
                case SLEIGH_PROC_X86_16_REAL: {
                    sla = std::string(proc_dir) +
                          std::string("/x86/data/languages/x86-64.sla");
                    pspec =
                        std::string(proc_dir) +
                        std::string("/x86/data/languages/x86-16-real.pspec");
                } break;
                default:
                    last_error = "unexpected arch-proc combination";
                    return NULL;
            }
        } break;
        case SLEIGH_ARCH_X86: {
            switch (proc) {
                case SLEIGH_PROC_X86: {
                    sla = std::string(proc_dir) +
                          std::string("/x86/data/languages/x86.sla");
                    pspec = std::string(proc_dir) +
                            std::string("/x86/data/languages/x86.pspec");
                } break;
                default:
                    last_error = "unexpected arch-proc combination";
                    return NULL;
            }
        } break;
        default:
            last_error = "unexpected arch combination";
            return NULL;
    }

    TranslationContext* ctx = new TranslationContext();
    if (!ctx->loadSlaFile(sla.c_str())) {
        delete ctx;
        return NULL;
    }
    if (!ctx->loadPspecFile(pspec.c_str())) {
        delete ctx;
        return NULL;
    }
    return (sleigh_ctx_t)ctx;
}

void sleigh_destroy_context(sleigh_ctx_t _ctx)
{
    auto ctx = static_cast<TranslationContext*>(_ctx);
    if (ctx == nullptr)
        return;
    delete ctx;
}

void sleigh_get_all_registers(sleigh_ctx_t ctx, sleigh_register_t** registers,
                              size_t* size)
{
    std::map<ghidra::VarnodeData, std::string> regmap;
    ((TranslationContext*)ctx)->m_sleigh->getAllRegisters(regmap);

    sleigh_register_t* regs =
        (sleigh_register_t*)calloc(sizeof(sleigh_register_t), regmap.size());

    int i = 0;
    for (const auto& [varnode, name] : regmap) {
        sleigh_varnode_t v = {
            .space  = (sleigh_address_space_t)varnode.space,
            .offset = varnode.offset,
            .size   = varnode.size,
        };
        strncpy(regs[i].name, name.c_str(), sizeof(regs[i].name) - 1UL);
        regs[i].varnode = v;
        i++;
    }

    *size      = regmap.size();
    *registers = regs;
}

bool sleigh_get_register(sleigh_ctx_t _ctx, const char* name,
                         sleigh_varnode_t* reg)
{
    auto ctx = static_cast<TranslationContext*>(_ctx);
    return ctx->getRegister(name, reg);
}

sleigh_translation_result_t*
sleigh_translate(sleigh_ctx_t _ctx, const uint8_t* bytes, uint32_t num_bytes,
                 uint64_t address, uint32_t max_instructions,
                 int bb_terminating)
{
    auto ctx = static_cast<TranslationContext*>(_ctx);
    return ctx->translate(bytes, num_bytes, address, max_instructions,
                          bb_terminating);
}

void sleigh_destroy_translation_result(sleigh_translation_result_t* r)
{
    if (r)
        delete owner_of(r, &TranslationResult::m_res);
}

const char* sleigh_get_space_name(sleigh_address_space_t space)
{
    return ((ghidra::AddrSpace*)space)->getName().c_str();
}

sleigh_address_space_t sleigh_get_space_by_name(sleigh_ctx_t _ctx,
                                                const char*  name)
{
    auto ctx = static_cast<TranslationContext*>(_ctx);
    return (sleigh_address_space_t)ctx->m_sleigh->getSpaceByName(name);
}

bool sleigh_varnode_is_register(sleigh_varnode_t* varnode)
{
    return strcmp(sleigh_get_space_name(varnode->space), "register") == 0;
}

bool sleigh_varnode_is_unique(sleigh_varnode_t* varnode)
{
    return strcmp(sleigh_get_space_name(varnode->space), "unique") == 0;
}

bool sleigh_varnode_is_const(sleigh_varnode_t* varnode)
{
    return strcmp(sleigh_get_space_name(varnode->space), "const") == 0;
}

const char* sleigh_get_register_name(sleigh_ctx_t      _ctx,
                                     sleigh_varnode_t* varnode)
{
    if (!sleigh_varnode_is_register(varnode))
        return NULL;

    auto ctx = static_cast<TranslationContext*>(_ctx);
    return ctx->getRegisterName((ghidra::AddrSpace*)varnode->space,
                                varnode->offset, varnode->size);
}

sleigh_address_space_t sleigh_varnode_get_const_space(sleigh_varnode_t* varnode)
{
    if (!sleigh_varnode_is_const(varnode))
        return NULL;
    return (sleigh_address_space_t)varnode->offset;
}

const char* sleigh_get_last_error() { return last_error.c_str(); }

const char* sleigh_opcode_name(sleigh_opcode_t op)
{
    switch (op) {
#define DEC_OP(oid, oname, odesc)                                              \
    case OP(oname):                                                            \
        return #oname;
#define INV_OP(oid, oname, odesc)
        OPS_X
#undef DEC_OP
#undef INV_OP
        default:
            break;
    }
    return "unknown";
}

// *** floats ***

sleigh_float_format_t sleigh_get_host_float(sleigh_ctx_t _ctx, int32_t size)
{
    if (size <= 0)
        return nullptr;

    auto ctx = static_cast<TranslationContext*>(_ctx);
    ctx->m_sleigh->setDefaultFloatFormats();

    std::vector<const ghidra::FloatFormat*> v;
    for (int i = 0; i < 32; ++i) {
        const ghidra::FloatFormat* ff = ctx->m_sleigh->getFloatFormat(i);
        if (ff && ff->getSize() == size)
            return (sleigh_float_format_t)ff;
    }
    return nullptr;
}

int32_t float_format_get_size(sleigh_float_format_t _ff)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->getSize();
}

uint64_t float_format_get_encoding(sleigh_float_format_t _ff, double val)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->getEncoding(val);
}

double float_format_get_host_float(sleigh_float_format_t _ff, uint64_t encoding)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;

    ghidra::FloatFormat::floatclass type;
    return ff->getHostFloat(encoding, &type);
}

uint64_t float_format_convert_encoding(sleigh_float_format_t _from,
                                       sleigh_float_format_t _to,
                                       uint64_t              encoding)
{
    const ghidra::FloatFormat* from = (const ghidra::FloatFormat*)_from;
    const ghidra::FloatFormat* to   = (const ghidra::FloatFormat*)_to;

    return to->convertEncoding(encoding, from);
}

uint64_t float_format_op_Equal(sleigh_float_format_t _ff, uint64_t a,
                               uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opEqual(a, b);
}

uint64_t float_format_op_NotEqual(sleigh_float_format_t _ff, uint64_t a,
                                  uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opNotEqual(a, b);
}

uint64_t float_format_op_Less(sleigh_float_format_t _ff, uint64_t a, uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opLess(a, b);
}

uint64_t float_format_op_LessEqual(sleigh_float_format_t _ff, uint64_t a,
                                   uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opLessEqual(a, b);
}

uint64_t float_format_op_Nan(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opNan(a);
}

uint64_t float_format_op_Add(sleigh_float_format_t _ff, uint64_t a, uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opAdd(a, b);
}

uint64_t float_format_op_Div(sleigh_float_format_t _ff, uint64_t a, uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opDiv(a, b);
}

uint64_t float_format_op_Mult(sleigh_float_format_t _ff, uint64_t a, uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opMult(a, b);
}

uint64_t float_format_op_Sub(sleigh_float_format_t _ff, uint64_t a, uint64_t b)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opSub(a, b);
}

uint64_t float_format_op_Neg(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opNeg(a);
}

uint64_t float_format_op_Abs(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opAbs(a);
}

uint64_t float_format_op_Sqrt(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opSqrt(a);
}

uint64_t float_format_op_Trunc(sleigh_float_format_t _ff, uint64_t a,
                               uint32_t sizeout)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opTrunc(a, sizeout);
}

uint64_t float_format_op_Ceil(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opCeil(a);
}

uint64_t float_format_op_Floor(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opFloor(a);
}

uint64_t float_format_op_Round(sleigh_float_format_t _ff, uint64_t a)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opRound(a);
}

uint64_t float_format_op_Int2Float(sleigh_float_format_t _ff, uint64_t a,
                                   uint32_t sizein)
{
    const ghidra::FloatFormat* ff = (const ghidra::FloatFormat*)_ff;
    return ff->opInt2Float(a, sizein);
}
