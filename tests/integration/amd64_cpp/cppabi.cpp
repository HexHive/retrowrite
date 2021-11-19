
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

namespace __cxxabiv1 {
    struct __class_type_info {
        virtual void foo() {}
    } ti;
}

#define EXCEPTION_BUFF_SIZE 255
char exception_buff[EXCEPTION_BUFF_SIZE];

extern "C" {

void* __cxa_allocate_exception(size_t thrown_size)
{
    if (thrown_size > EXCEPTION_BUFF_SIZE) printf("Exception too big");
    return &exception_buff;
}

void __cxa_free_exception(void *thrown_exception);


#include <unwind.h>
#include <typeinfo>

typedef void (*unexpected_handler)(void);
typedef void (*terminate_handler)(void);

struct __cxa_exception { 
	std::type_info *	exceptionType;
	void (*exceptionDestructor) (void *); 
	unexpected_handler	unexpectedHandler;
	terminate_handler	terminateHandler;
	__cxa_exception *	nextException;

	int			handlerCount;
	int			handlerSwitchValue;
	const char *		actionRecord;
	const char *		languageSpecificData;
	void *			catchTemp;
	void *			adjustedPtr;

	_Unwind_Exception	unwindHeader;
};

void __cxa_throw(void* thrown_exception,
                 std::type_info *tinfo,
                 void (*dest)(void*))
{
    __cxa_exception *header = ((__cxa_exception *) thrown_exception - 1);


    printf(">> CXA_THROW 0x%08lx\n", (uintptr_t)tinfo);
    printf(">> CXA_THROW %s\n", tinfo->name());

    // We need to save the type info in the exception header _Unwind_ will
    // receive, otherwise we won't be able to know it when unwinding
    header->exceptionType = tinfo;

    _Unwind_RaiseException(&header->unwindHeader);

    // __cxa_throw never returns
    printf("no one handled __cxa_throw, terminate!\n");
    exit(0);
}


void __cxa_begin_catch()
{
    printf(">> Begin Catch\n");
}

void __cxa_end_catch()
{
    printf(">> End Catch\n");
}




/**********************************************/

int readSLEB128(const uint8_t* data)
{
    uintptr_t result = 0;
    uintptr_t shift = 0;
    unsigned char byte;
    const uint8_t *p = data;
    do
    {
        byte = *p++;
        result |= static_cast<uintptr_t>(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);

    if ((byte & 0x40) && (shift < (sizeof(result) << 3)))
        result |= static_cast<uintptr_t>(~0) << shift;

    return static_cast<int>(result);
}




/**
 * The LSDA is a read only place in memory; we'll create a typedef for
 * this to avoid a const mess later on; LSDA_ptr refers to readonly and
 * &LSDA_ptr will be a non-const pointer to a const place in memory
 */
typedef const uint8_t* LSDA_ptr;

struct LSDA_Header {
    /**
     * Read the LSDA table into a struct; advances the lsda pointer
     * as many bytes as read
     */
    LSDA_Header(LSDA_ptr *lsda) {
        LSDA_ptr read_ptr = *lsda;

        // Copy the LSDA fields
        start_encoding = read_ptr[0];
        type_encoding = read_ptr[1];
        type_table_offset = read_ptr[2];

        // Advance the lsda pointer
        *lsda = read_ptr + sizeof(LSDA_Header);
    }

    uint8_t start_encoding;
    uint8_t type_encoding;

    // This is the offset, from the end of the header, to the types table
    uint8_t type_table_offset;
};

struct Call_Site_Header {
    // Same as other LSDA constructors
    Call_Site_Header(LSDA_ptr *lsda) {
        LSDA_ptr read_ptr = *lsda;
        encoding = read_ptr[0];
        length = read_ptr[1];
        *lsda = read_ptr + sizeof(Call_Site_Header);
    }

    uint8_t encoding;
    uint8_t length;
};

struct Call_Site {
    // Same as other LSDA constructors
    Call_Site(LSDA_ptr *lsda) {
        LSDA_ptr read_ptr = *lsda;
        start = read_ptr[0];
        len = read_ptr[1];
        lp = read_ptr[2];
        action = read_ptr[3];
        *lsda = read_ptr + sizeof(Call_Site);
    }

    Call_Site() { }

    // Note start, len and lp would be void*'s, but they are actually relative
    // addresses: start and lp are relative to the start of the function, len
    // is relative to start
 
    // Offset into function from which we could handle a throw
    uint8_t start;
    // Length of the block that might throw
    uint8_t len;
    // Landing pad
    uint8_t lp;
    // Offset into action table + 1 (0 means no action)
    // Used to run destructors
    uint8_t action;

    bool has_landing_pad() const { return lp; }

    /**
     * Returns true if the instruction pointer for this call frame
     * (throw_ip) is in the range of the landing pad for this call
     * site; if true that means the exception was thrown from within
     * this try/catch block
     */
    bool valid_for_throw_ip(uintptr_t func_start, uintptr_t throw_ip) const
    {
        // Calculate the range of the instruction pointer valid for this
        // landing pad; if this LP can handle the current exception then
        // the IP for this stack frame must be in this range
        uintptr_t try_start = func_start + this->start;
        uintptr_t try_end = func_start + this->start + this->len;

        // Check if this is the correct LP for the current try block
        if (throw_ip < try_start) return false;
        if (throw_ip > try_end) return false;

        // The current exception was thrown from this landing pad
        return true;
    }
};

/**
 * A class to read the language specific data for a function
 */
struct LSDA
{
    LSDA_Header header;

    // The types_table_start holds all the types this stack frame
    // could handle (this table will hold pointers to struct
    // type_info so this is actually a pointer to a list of ptrs
    const void** types_table_start;

    // With the call site header we can calculate the lenght of the
    // call site table
    Call_Site_Header cs_header;

    // A pointer to the start of the call site table
    const LSDA_ptr cs_table_start;

    // A pointer to the end of the call site table
    const LSDA_ptr cs_table_end;

    // A pointer to the start of the action table, where an action is
    // defined for each call site
    const LSDA_ptr action_tbl_start;

    LSDA(LSDA_ptr raw_lsda) :
        // Read LSDA header for the LSDA, advance the ptr
        header(&raw_lsda),

        // Get the start of the types table (it's actually the end of the
        // table, but since the action index will hold a negative index
        // for this table we can say it's the beginning
        types_table_start( (const void**)(raw_lsda + header.type_table_offset) ),

        // Read the LSDA CS header
        cs_header(&raw_lsda),

        // The call site table starts immediatelly after the CS header
        cs_table_start(raw_lsda),

        // Calculate where the end of the LSDA CS table is
        cs_table_end(raw_lsda + cs_header.length),

        // Get the start of action tables
        action_tbl_start( cs_table_end )
    {
    }
   

    Call_Site next_cs_entry;
    LSDA_ptr next_cs_entry_ptr;

    const Call_Site* next_call_site_entry(bool start=false)
    {
        if (start) next_cs_entry_ptr = cs_table_start;

        // If we went over the end of the table return NULL
        if (next_cs_entry_ptr >= cs_table_end)
            return NULL;

        // Copy the call site table and advance the cursor by sizeof(Call_Site).
        // We need to copy the struct here because there might be alignment
        // issues otherwise
        next_cs_entry = Call_Site(&next_cs_entry_ptr);

        return &next_cs_entry;
    }


    /**
     * Returns a pointer to the action entry for a call site entry or
     * null if the CS has no action
     */
    const LSDA_ptr get_action_for_call_site(const Call_Site *cs) const
    {
        if (cs->action == 0) return NULL;

        const size_t action_offset = cs->action - 1;
        return this->action_tbl_start + action_offset;
    }


    /**
     * An entry in the action table
     */
    struct Action {
        // An index into the types table
        int type_index;

        // Offset for the next action, relative from this byte (this means
        // that the next action will begin exactly at the address of
        // &next_offset - next_offset itself
        int next_offset;

        // A pointer to the raw action, which we need to get the next
        // action:
        //   next_action_offset = raw_action_ptr[1]
        //   next_action_ptr = &raw_action_ptr[1] + next_action_offset
        LSDA_ptr raw_action_ptr;

    } current_action;


    /**
     * Gets the first action for a specific call site
     */
    const Action* get_first_action_for_cs(const Call_Site *cs)
    {
        // The call site may have no associated action (in that case
        // it should be a cleanup)
        if (cs->action == 0) return NULL;

        // The action in the CS is 1 based: 0 means no action and
        // 1 is the element 0 on the action table
        const size_t action_offset = cs->action - 1;
        LSDA_ptr action_raw = this->action_tbl_start + action_offset;

        current_action.type_index = action_raw[0];
        current_action.next_offset = readSLEB128( &action_raw[1] );
        current_action.raw_action_ptr = &action_raw[0];

        printf(">> Action CURRENT: TYPE %d NEXT %08x\n", current_action.type_index, current_action.next_offset);

        return &current_action;
    }

    /**
     * Gets the next action, if any, for a CS (after calling
     * get_first_action_for_cs)
     */
    const Action* get_next_action() {
        // If the current_action is the last one then the
        // offset for the next one will be 0
        if (current_action.next_offset == 0) return NULL;

        // To move to the next action we must use raw_action_ptr + 1
        // because the offset is from the next_offset place itself and
        // not from the start of the struct:
        LSDA_ptr action_raw = current_action.raw_action_ptr + 1 +
                                        current_action.next_offset;

        current_action.type_index = action_raw[0];
        current_action.next_offset = readSLEB128( &action_raw[1] );
        current_action.raw_action_ptr = &action_raw[0];

        printf(">> Action NEXT: TYPE %d NEXT %08x\n", current_action.type_index, current_action.next_offset);

        return &current_action;
    }

    /**
     * Returns the type from the types table defined for an action
     */
    const std::type_info* get_type_for(const Action* action) const
    {
        // The index starts at the end of the types table
        int idx = -1 * action->type_index;
        const void* catch_type_info = this->types_table_start[idx];
        printf(">> TYPE: INDEX %d TYPE_INFO: 0x%08lx\n", action->type_index, (uintptr_t)catch_type_info);
        return (const std::type_info *) catch_type_info;
    }
};


/**********************************************/


bool can_handle(const std::type_info *thrown_exception,
                const std::type_info *catch_type)
{

    printf(">> CAN_HANDLE: THROWN: 0x%08lx CATCH TYPE: 0x%08lx\n", (uintptr_t)thrown_exception, (uintptr_t)catch_type);
    printf(">>             Catch Type %s\n", catch_type->name());
    printf(">>             Thrown Exception %s\n", thrown_exception->name());
    // If the catch has no type specifier we're dealing with a catch(...)
    // and we can handle this exception regardless of what it is
    if (not catch_type) return true;

    // Naive type comparisson: only check if the type name is the same
    // This won't work with any kind of inheritance
    if (thrown_exception->name() == catch_type->name())
        return true;

    // If types don't match just don't handle the exception
    return false;
}


_Unwind_Reason_Code
    run_landing_pad(
                 _Unwind_Exception* unwind_exception,
                 _Unwind_Context* context,
                 int exception_type_idx,
                 uintptr_t lp_address)
{
    int r0 = __builtin_eh_return_data_regno(0);
    int r1 = __builtin_eh_return_data_regno(1);

    _Unwind_SetGR(context, r0, (uintptr_t)(unwind_exception));
    _Unwind_SetGR(context, r1, (uintptr_t)(exception_type_idx));
    _Unwind_SetIP(context, lp_address);

    return _URC_INSTALL_CONTEXT;
}


_Unwind_Reason_Code __gxx_personality_v0 (
                             int version,
                             _Unwind_Action actions,
                             uint64_t exceptionClass,
                             _Unwind_Exception* unwind_exception,
                             _Unwind_Context* context)
{
    // Calculate what the instruction pointer was just before the
    // exception was thrown for this stack frame
    uintptr_t throw_ip = _Unwind_GetIP(context) - 1;

    // Get a ptr to the start of the function for this stack frame;
    // this is needed because a lot of the addresses in the LSDA are
    // actually offsets from func_start
    uintptr_t func_start = _Unwind_GetRegionStart(context);

    // Get a pointer to the type_info of the exception being thrown
    __cxa_exception *exception_header =(__cxa_exception*)(unwind_exception+1)-1;
    std::type_info *thrown_exception_type = exception_header->exceptionType;

    // Get a pointer to the raw memory address of the LSDA
    LSDA_ptr raw_lsda = (LSDA_ptr) _Unwind_GetLanguageSpecificData(context);

    // Create an object to hide some part of the LSDA processing
    LSDA lsda(raw_lsda);

    // Go through each call site in this stack frame to check whether
    // the current exception can be handled here
    for(const Call_Site *cs = lsda.next_call_site_entry(true);
            cs != NULL;
            cs = lsda.next_call_site_entry())
    {
        printf(">> CALL SITE\n");

        // If there's no landing pad we can't handle this exception
        if (not cs->has_landing_pad()) continue;

        printf(">>> HAS LANDING PAD\n");
        printf(">>> FUNC_START: 0x%08lx THROW_IP: 0x%08lx\n", (uintptr_t)func_start, (uintptr_t) throw_ip);

        // Calculate the range of the instruction pointer valid for this
        // landing pad; if this LP can handle the current exception then
        // the IP for this stack frame must be in this range
        if (not cs->valid_for_throw_ip(func_start, throw_ip)) continue;

        // Iterate all the actions for this call site
        for (const LSDA::Action* action = lsda.get_first_action_for_cs(cs);
                action != NULL;
                action = lsda.get_next_action())
        {
            if (action->type_index == 0)
            {
                // If there is an action entry but it doesn't point to any
                // type, it means this is actually a cleanup block and we
                // should run it anyway
                //
                // Of course the cleanup should only run on the cleanup phase
                if (actions & _UA_CLEANUP_PHASE)
                {
                    return run_landing_pad(unwind_exception, context,
                                    action->type_index, func_start + cs->lp);
                }
            } else {
                // Get the types this action can handle
                const std::type_info *catch_type = lsda.get_type_for(action);

                if (can_handle(catch_type, thrown_exception_type))
                {
                    // If we are on search phase, tell _Unwind_ we can handle this one
                    if (actions & _UA_SEARCH_PHASE) return _URC_HANDLER_FOUND;

                    // If we are not on search phase then we are on _UA_CLEANUP_PHASE
                    // and we need to install the context
                    return run_landing_pad(unwind_exception, context,
                                    action->type_index, func_start + cs->lp);
                }
            }
        }
    }

    return _URC_CONTINUE_UNWIND;
}

}
