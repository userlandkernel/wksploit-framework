var AARCH64_INSN_CLS_UNKNOWN = 0x0;
var AARCH64_INSN_CLS_DP_IMM = 0x1;
var AARCH64_INSN_CLS_DP_REG = 0x2;
var AARCH64_INSN_CLS_DP_FPSIMD = 0x3;
var AARCH64_INSN_CLS_LDST = 0x4;
var AARCH64_INSN_CLS_BR_SYS = 0x5;

var AARCH64_INSN_HINT_NOP = 0x0 << 5;
var AARCH64_INSN_HINT_YIELD = 0x1 << 5;
var AARCH64_INSN_HINT_WFE = 0x2 << 5;
var AARCH64_INSN_HINT_WFI = 0x3 << 5;
var AARCH64_INSN_HINT_SEV = 0x4 << 5;
var AARCH64_INSN_HINT_SEVL = 0x5 << 5;

var aarch64_insn_encoding_class = [
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_REG,
	AARCH64_INSN_CLS_DP_FPSIMD,
	AARCH64_INSN_CLS_DP_IMM,
	AARCH64_INSN_CLS_DP_IMM,
	AARCH64_INSN_CLS_BR_SYS,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_REG,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_FPSIMD
];

var aarch64_get_insn_class = function(u32_insn)
{
	return aarch64_insn_encoding_class[(u32_insn >> 25) & 0xf];
}

function aarch64_insn_is_nop(u32_insn)
{
	// First we need to detect whether the instruction is a hint
	// NOP should always have a hint else it is invalid
	if(!aarch64_insn_is_hint(u32_insn))
		return false;

	switch(u32_insn & 0xFE0)
	{
		case AARCH64_INSN_HINT_YIELD:
		case AARCH64_INSN_HINT_WFE:
		case AARCH64_INSN_HINT_SEV:
		case AARCH64_INSN_HINT_SEVL:
			return false;
		default:
			return true;
	}
};

function aarch64_insn_hotpatch_safe(u32_insn = -1)
{

	if(typeof u32_insn !== 'number')
		return false;

	if(u32_insn < 0)
		return false;

	if(aarch64_get_insn_class(u32_insn) != AARCH64_INSN_CLS_BR_SYS)
		return false;

	return  aarch64_isn_is_b(u32_insn) ||
			aarch64_isn_is_bl(u32_insn) ||
			aarch64_isn_is_svc(u32_insn) ||
			aarch64_isn_is_hvc(u32_insn) ||
			aarch64_isn_is_smc(u32_insn) ||
			aarch64_isn_is_brk(u32_insn) ||
			aarch64_isn_is_nop(u32_insn);
}

var AARCH64_INSN_FUNCS = new Array();
AARCH64_INSN_FUNCS["b"] = {mask: 0xFC000000, value: 0x14000000};
AARCH64_INSN_FUNCS["bl"] = {mask: 0xFC000000, value: 0x94000000};
AARCH64_INSN_FUNCS["svc"] = {mask: 0xFFE0001F, value: 0xD4000001};
AARCH64_INSN_FUNCS["hvc"] = {mask: 0xFFE0001F , value: 0xD4000002};
AARCH64_INSN_FUNCS["smc"] = {mask: 0xFFE0001F, value: 0xD4000003};
AARCH64_INSN_FUNCS["brk"] = {mask: 0xFFE0001F, value: 0xD4200000};
AARCH64_INSN_FUNCS["hint"] = {mask: 0xFFFFF01F, value: 0xD503201F};


function aarch64_insn_is_b(code = 0)
{
	return (code & AARCH64_INSN_FUNCS["b"].mask) == AARCH64_INSN_FUNCS["b"].value;
}

function aarch64_insn_is_bl(code)
{
	return (code & AARCH64_INSN_FUNCS["bl"].mask) == AARCH64_INSN_FUNCS["bl"].value;
}

function aarch64_insn_is_hvc(code)
{
	return (code & AARCH64_INSN_FUNCS["hvc"].mask) == AARCH64_INSN_FUNCS["hvc"].value;
}

function aarch64_insn_is_smc(code)
{
	return (code & AARCH64_INSN_FUNCS["smc"].mask) == AARCH64_INSN_FUNCS["smc"].value;
}

function aarch64_insn_is_brk(code)
{
	return (code & AARCH64_INSN_FUNCS["brk"].mask) == AARCH64_INSN_FUNCS["brk"].value;
}

function aarch64_insn_is_hint(code)
{
	return (code & AARCH64_INSN_FUNCS["hint"].mask) == AARCH64_INSN_FUNCS["hint"].value;
}

function find_gadget(buffer, abbr)
{
	var u32 = new Uint32Array(buffer);
	for(i = 0; i < buffer.byteLength; i++)
	{
		var u32_insn = u32[i];
		if(typeof AARCH64_INSN_FUNCS[abbr] === "undefined")
		{
			return -1;
		}
		if((u32_insn & AARCH64_INSN_FUNCS[abbr].mask) == AARCH64_INSN_FUNCS[abbr].value)
			return i;
	}
	return -1;
}

