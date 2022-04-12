package main

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
)

/*
 * RegisterSet represents a subset of all registers. Each register is
 * associated to a bit in the uint64. If the bit is 1, the register belongs
 * to the RegisterSet and if it's 0 the register doesn't belong to the set.
 * Using this representation is much more efficient than using a map or a list
 * but it can only represent a fixed number of registers.
 */
type RegisterSet uint32

// AnalysisResult is the result of a register analysis.
type AnalysisResult struct {
	/*
	 * FreeRegs is a slice containing the names of the registers that are free
	 * at each instruction.
	 */
	FreeRegs [][]string

	// FunctionName is the name of the function that was analyzed.
	FunctionName string
}

// Address is the address of an object in an ELF file.
type Address struct {
	// SectionName is the name of the section that contains the object.
	SectionName string
	// Offset is the offset form the start of the section.
	Offset uint64
}

// InstructionInfo contains data about an instruction in a program.
type InstructionInfo struct {
	// Address is the address of the instruction.
	Address Address

	/*
	 * Successors is the list of successors of the instruction. A successor can
	 * be an integer (encoded as float64 because that's what Go uses for JSON
	 * numbers) if the successor is an instruction, or a string if the
	 * successor is special ("ret" if the instruction returns from
	 * the function, "call" if the instruction is a function call, and "undef"
	 * if the next instruction is unknown, for example if the instruction is an
	 * indirect jump with unknown target).
	 */
	Successors []interface{}

	/*
	 * RegsWritten is a slice of strings containing the names of the registers
	 * that this instruction writes to.
	 */
	RegsWritten []string `json:"regs_written"`

	// RegsWrittenSet is the same as RegsWritten but in bitset form.
	RegsWrittenSet RegisterSet

	/*
	 * RegsRead is a slice of strings containing the names of the registers
	 * that this instruction reads from.
	 */
	RegsRead []string `json:"regs_read"`

	// RegsReadSet is the same as RegsRead but in bitset form.
	RegsReadSet RegisterSet
}

// FunctionInfo contains information about a function.
type FunctionInfo struct {
	// Address is the starting address of the function.
	Address Address

	/*
	 *Instructions contains an InstructionInfo structure for each instruction
	 * in the function.
	 */
	Instructions []InstructionInfo

	BbStarts []string
}

// RegisterInfo contains information about an x86 register
type RegisterInfo struct {
	/*
	 * FullRegisterName is the name of the full (64-bit) register corresponding
	 * to this register. For example the FullRegisterName of ah is rax.
	 */
	FullRegisterName string

	// RegisterSize is the size of this register in bits.
	RegisterSize int
}

/*
 * maxIterations is the maximum number of iterations that the register analysis
 * will run for before bailing out.
 */
const maxIterations = 8192

// allRegs is a list of the names of all registers.
var allRegs = []string{
	"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags",
}

// allRegsSet is a RegisterSet that contains all the registers.
var allRegsSet = regSetFromRegList(allRegs)

/*
 * subRegs maps subregister names to the name of the full register
 * (e.g. al -> rax, esp -> rsp).
 */
var subRegs = initializeSubRegs()

var regsUsedByRet = regSetFromRegList([]string{
	"rbx", "rbp", "rsp", "r12", "r13", "r14", "r15", "rax", "rdx", "r10",
	"r11", "r8", "r9", "rcx", "rdi", "rsi",
})

var regsUsedByCall = regSetFromRegList([]string{
	"rbx", "rbp", "rsp", "r12", "r13", "r14", "r15", "rdi", "rsi", "rdx",
	"rcx", "r8", "r9", "rax",
})

// regNameToUnitSet creates a RegisterSet containing only one register
func regNameToUnitSet(regName string) RegisterSet {
	for i, r := range allRegs {
		if subRegs[regName].FullRegisterName == r {
			return 1 << uint(i)
		}
	}

	panic(fmt.Sprintf("Unknown register name %s", regName))
}

// regSetFromRegList creates a RegisterSet from a list of register names
func regSetFromRegList(regList []string) RegisterSet {
	ret := RegisterSet(0)

	if len(regList) > 32 {
		panic("Register list too long")
	}

	for _, r := range regList {
		if r == "ds" || r == "gs" {
			// Skip segment registers
			continue
		}

		ret = ret.regSetUnion(regNameToUnitSet(r))
	}

	return ret
}

// regSetDifference computes the set difference between two register sets.
func (rs RegisterSet) regSetDifference(other RegisterSet) RegisterSet {
	return (rs ^ other) & rs
}

// regSetUnion computes the set union between two register sets.
func (rs RegisterSet) regSetUnion(other RegisterSet) RegisterSet {
	return rs | other
}

// regSetComplement computes the complement of a register set
func (rs RegisterSet) regSetComplement() RegisterSet {
	return ^rs
}

// regSetComplement computes the size of a register set
func (rs RegisterSet) regSetSize() int {
	return bits.OnesCount32(uint32(rs))
}

// regSetToRegList converts a RegisterSet to a list of register names
func (rs RegisterSet) regSetToRegList() []string {
	ret := make([]string, 0)

	for i, r := range allRegs {
		if (rs & (1 << uint(i))) != 0 && r != "rip" && r != "rsp" {
			ret = append(ret, r)
		}
	}

	return ret
}

func analyzeInstruction(i int, functionName string, functionInfo *FunctionInfo, usedRegs []RegisterSet) bool {
	instructionInfo := functionInfo.Instructions[i]

	reguses := instructionInfo.RegsReadSet
	regwrites := instructionInfo.RegsWrittenSet.regSetDifference(reguses)

	for _, successor := range instructionInfo.Successors {
		var regsUsedBySuccessor RegisterSet

		switch v := successor.(type) {
		case float64:
			succIndex := int(v)
			if succIndex > len(usedRegs) {
				panic(fmt.Sprintf("Successor index out of range in %s instruction %d (%d/%d)", functionName, i, succIndex, len(usedRegs)))
			} else if succIndex == len(usedRegs) {
				// tail call?
				regsUsedBySuccessor = allRegsSet
			} else {
				regsUsedBySuccessor = usedRegs[succIndex]
			}

		case string:
			switch v {
			case "ret":
				regsUsedBySuccessor = regsUsedByRet

			case "call":
				regsUsedBySuccessor = regsUsedByCall

			case "undef":
				regsUsedBySuccessor = allRegsSet
			}
		}

		regsUsedBySuccessor = regsUsedBySuccessor.regSetDifference(regwrites)
		reguses = reguses.regSetUnion(regsUsedBySuccessor)
	}

	if reguses != usedRegs[i] {
		usedRegs[i] = reguses
		return true
	}

	return false
}

func analyzeFunction(functionName string, functionInfo *FunctionInfo) AnalysisResult {
	usedRegs := make([]RegisterSet, 0, len(functionInfo.Instructions))

	// Initialize the data so that every instruction initially uses every register
	for _ = range functionInfo.Instructions {
		usedRegs = append(usedRegs, allRegsSet)
	}

	// Convert to register set representation
	for i := range functionInfo.Instructions {
		regsRead := functionInfo.Instructions[i].RegsRead
		regsWritten := functionInfo.Instructions[i].RegsWritten
		functionInfo.Instructions[i].RegsReadSet = regSetFromRegList(regsRead)
		functionInfo.Instructions[i].RegsWrittenSet = regSetFromRegList(regsWritten)

		for _, rw := range regsWritten {
			rinfo := subRegs[rw]
			if rinfo.RegisterSize < 32 {
				/*
				 * If an instruction writes to a 16-bit or 8-bit register it
				 * should also be marked as reading from the full register
				 * since the rest of the register is preserved by the write.
				 * otherwise the register analysis will be wrong.
				 *
				 * Consider the following example:
				 *     xor ecx, ecx ; zeros all of rcx because 32-bit results
				 *                  ; are zero-extended to 64-bit
				 *
				 *     [other stuff...]
				 *
				 *     setz cl      ; Capstone marks this instruction as writing
				 *                  ; from cl but not reading from it
				 *
				 *     add ecx, ecx ; after this instruction ecx = 0 or ecx = 2
				 *
				 * The analysis will see that setz writes to cl (and therefore
				 * to rcx) and will consider rcx to be free for <other stuff>
				 * to overwrite. This is a problem because setz (or any
				 * instruction that writes to a 8-bit or 16-bit register)
				 * preserves the rest of the register. If other_stuff
				 * overwrites rcx, the result won't be 0 or 2 but something
				 * else, which is bad.
				 *
				 * To fix this, we need to mark all instructions that write
				 * to a 8- or 16-bit register as also reading from that
				 * register.
				 */
				functionInfo.Instructions[i].RegsReadSet |= regNameToUnitSet(rinfo.FullRegisterName)
			}
		}
	}

	change := true

	for i := 0; i < maxIterations && change; i++ {
		change = false
		for i := range functionInfo.Instructions {
			change = change || analyzeInstruction(i, functionName, functionInfo, usedRegs)
		}
	}

	functionFreeRegs := make([][]string, 0, len(functionInfo.Instructions))

	// Compute the set of free registers as the complement of the set of used registers
	for _, instructionUsedRegs := range usedRegs {
		instructionFreeRegs := instructionUsedRegs.regSetComplement().regSetToRegList()
		functionFreeRegs = append(functionFreeRegs, instructionFreeRegs)
	}

	return AnalysisResult{FreeRegs: functionFreeRegs, FunctionName: functionName}
}

func initializeSubRegs() map[string]RegisterInfo {
	ret := make(map[string]RegisterInfo)

	for _, r := range allRegs {
		ret[r] = RegisterInfo{FullRegisterName: r, RegisterSize: 64}

		switch r {
		case "rax":
			fallthrough
		case "rbx":
			fallthrough
		case "rcx":
			fallthrough
		case "rdx":
			// eax, ...
			ret["e"+r[1:]] = RegisterInfo{FullRegisterName: r, RegisterSize: 32}
			// ax, ...
			ret[r[1:]] = RegisterInfo{FullRegisterName: r, RegisterSize: 16}
			// al, ...
			ret[r[1:2]+"l"] = RegisterInfo{FullRegisterName: r, RegisterSize: 8}
			// ah, ...
			ret[r[1:2]+"h"] = RegisterInfo{FullRegisterName: r, RegisterSize: 8}

		case "rdi":
			fallthrough
		case "rsi":
			// edi, ...
			ret["e"+r[1:]] = RegisterInfo{FullRegisterName: r, RegisterSize: 32}
			// di, ...
			ret[r[1:]] = RegisterInfo{FullRegisterName: r, RegisterSize: 16}
			// dil, ...
			ret[r[1:]+"l"] = RegisterInfo{FullRegisterName: r, RegisterSize: 8}

		case "r8":
			fallthrough
		case "r9":
			fallthrough
		case "r10":
			fallthrough
		case "r11":
			fallthrough
		case "r12":
			fallthrough
		case "r13":
			fallthrough
		case "r14":
			fallthrough
		case "r15":
			ret[r+"d"] = RegisterInfo{FullRegisterName: r, RegisterSize: 32}
			ret[r+"w"] = RegisterInfo{FullRegisterName: r, RegisterSize: 16}
			ret[r+"b"] = RegisterInfo{FullRegisterName: r, RegisterSize: 8}

		case "rbp":
			ret["ebp"] = RegisterInfo{FullRegisterName: r, RegisterSize: 32}
			ret["bp"] = RegisterInfo{FullRegisterName: r, RegisterSize: 16}
			ret["bpl"] = RegisterInfo{FullRegisterName: r, RegisterSize: 8}
		}
	}

	return ret
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <control flow information> <output>\n", os.Args[0])
		return
	}

	infile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening input file: %s\n", err)
		return
	}
	defer infile.Close()

	outfile, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Printf("Error creating output file: %s\n", err)
		return
	}
	defer outfile.Close()

	decoder := json.NewDecoder(infile)
	encoder := json.NewEncoder(outfile)

	// data maps the name of a function to its FunctionInfo structure
	var data map[string]*FunctionInfo

	// Load the function data
	err = decoder.Decode(&data)
	if err != nil {
		fmt.Printf("Decoding error: %s\n", err)
		return
	}

	/*
	 * completionChannel is used by the worker goroutines to send analysis
	 * results to the main goroutine
	 */
	completionChannel := make(chan AnalysisResult)

	/*
	 * Each function can be analyzed independently, spawn one goroutine per
	 * function to process them in parallel
	 */
	for functionName, functionInfo := range data {
		go func(fn string, fi *FunctionInfo) {
			analysisResult := analyzeFunction(fn, fi)

			completionChannel <- analysisResult
		}(functionName, functionInfo)
	}

	// Receive the results from the worker goroutines and write them out
	out := make(map[string]map[string]map[string][]string, len(data))

	for i := 0; i < len(data); i++ {
		ar := <-completionChannel
		out[ar.FunctionName] = make(map[string]map[string][]string)
		out[ar.FunctionName]["free_registers"] = make(map[string][]string)
		for i, fr := range ar.FreeRegs {
			out[ar.FunctionName]["free_registers"][fmt.Sprintf("%d", i)] = fr
		}
	}

	err = encoder.Encode(out)
	if err != nil {
		fmt.Printf("Encoding error: %s\n", err)
	}
}
