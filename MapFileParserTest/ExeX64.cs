using System;
using System.IO;
using Xunit;

namespace test
{
    public class ExeX64
    {
        const string _text = @" FileProtocolHandler

 Timestamp is 601a0342 (Wed Feb  3 10:58:26 2021)

 Preferred load address is 0000000140000000

 Start         Length     Name                   Class
 0001:00000000 00011b50H .text$mn                CODE
 0001:00011b50 00000020H .text$mn$00             CODE
 0001:00011b70 000005a0H .text$x                 CODE
 0002:00000000 00000320H .idata$5                DATA
 0002:00000320 00000010H .00cfg                  DATA
 0002:00000330 00000008H .CRT$XCA                DATA
 0002:00000338 00000008H .CRT$XCAA               DATA
 0002:00000340 00000008H .CRT$XCZ                DATA
 0002:00000348 00000008H .CRT$XIA                DATA
 0002:00000350 00000008H .CRT$XIAA               DATA
 0002:00000358 00000008H .CRT$XIAC               DATA
 0002:00000360 00000018H .CRT$XIC                DATA
 0002:00000378 00000008H .CRT$XIZ                DATA
 0002:00000380 00000008H .CRT$XPA                DATA
 0002:00000388 00000010H .CRT$XPX                DATA
 0002:00000398 00000008H .CRT$XPXA               DATA
 0002:000003a0 00000008H .CRT$XPZ                DATA
 0002:000003a8 00000008H .CRT$XTA                DATA
 0002:000003b0 00000010H .CRT$XTZ                DATA
 0002:000003b8 00000000H .gfids$y                DATA
 0002:000003c0 00007800H .rdata                  DATA
 0002:00007bc0 0000037cH .rdata$r                DATA
 0002:00007f3c 0000034cH .rdata$zzzdbg           DATA
 0002:00008288 00000008H .rtc$IAA                DATA
 0002:00008290 00000008H .rtc$IZZ                DATA
 0002:00008298 00000008H .rtc$TAA                DATA
 0002:000082a0 00000010H .rtc$TZZ                DATA
 0002:000082b0 00001518H .xdata                  DATA
 0002:000097c8 000001dcH .xdata$x                DATA
 0002:000099a4 00000000H .edata                  DATA
 0002:000099a4 00000064H .idata$2                DATA
 0002:00009a08 00000018H .idata$3                DATA
 0002:00009a20 00000320H .idata$4                DATA
 0002:00009d40 00000706H .idata$6                DATA
 0003:00000000 00000ad0H .data                   DATA
 0003:00000ad0 00000120H .data$r                 DATA
 0003:00000bf0 00001498H .bss                    DATA
 0004:00000000 000013b0H .pdata                  DATA
 0005:00000000 000004e0H .rsrc$01                DATA
 0005:000004e0 00016ec0H .rsrc$02                DATA

  Address         Publics by Value              Rva+Base               Lib:Object

 0000:00000000       __hybrid_code_map_count    0000000000000000     <absolute>
 0000:00000000       __hybrid_code_map          0000000000000000     <absolute>
 0000:00000000       __guard_iat_count          0000000000000000     <absolute>
 0000:00000000       __volatile_metadata        0000000000000000     <absolute>
 0000:00000000       __guard_longjmp_count      0000000000000000     <absolute>
 0000:00000000       __guard_longjmp_table      0000000000000000     <absolute>
 0000:00000000       __guard_iat_table          0000000000000000     <absolute>
 0000:00000000       __guard_fids_count         0000000000000000     <absolute>
 0000:00000000       ___safe_se_handler_count   0000000000000000     <absolute>
 0000:00000000       __enclave_config           0000000000000000     <absolute>
 0000:00000000       ___safe_se_handler_table   0000000000000000     <absolute>
 0000:00000000       __guard_fids_table         0000000000000000     <absolute>
 0000:00000000       __hybrid_auxiliary_iat     0000000000000000     <absolute>
 0000:00000000       __dynamic_value_reloc_table 0000000000000000     <absolute>
 0000:00000100       __guard_flags              0000000000000100     <absolute>
 0000:00000000       __ImageBase                0000000140000000     <linker-defined>
 0001:00001060       ??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 0000000140002060 f i FileProtocolHandler.obj
 0001:00001090       ??1?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@QEAA@XZ 0000000140002090 f i FileProtocolHandler.obj
 0001:000012b0       wWinMain                   00000001400022b0 f   FileProtocolHandler.obj
 0001:000018c0       ?OnCommand@@YA_JPEAUHWND__@@H0I@Z 00000001400028c0 f   FileProtocolHandler.obj
 0001:00001c50       ?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 0000000140002c50 f   FileProtocolHandler.obj
 0001:00001fb0       DialogProc                 0000000140002fb0 f   FileProtocolHandler.obj
 0001:00001fe0       ?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 0000000140002fe0 f i FileProtocolHandler.obj
 0001:00002070       ??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ 0000000140003070 f i FileProtocolHandler.obj
 0001:000020e0       ??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 00000001400030e0 f i FileProtocolHandler.obj
 0001:00002180       ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 0000000140003180 f i FileProtocolHandler.obj
 0001:00002290       ??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 0000000140003290 f i FileProtocolHandler.obj
 0001:00002400       ??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 0000000140003400 f i FileProtocolHandler.obj
 0001:00002560       ??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 0000000140003560 f i FileProtocolHandler.obj
 0001:00002720       ?_Xlen@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@SAXXZ 0000000140003720 f i FileProtocolHandler.obj
 0001:00002740       ?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 0000000140003740 f i FileProtocolHandler.obj
 0001:000027d0       ?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 00000001400037d0 f i FileProtocolHandler.obj
 0001:000028d0       ??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 00000001400038d0 f i FileProtocolHandler.obj
 0001:00002a40       ??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 0000000140003a40 f i FileProtocolHandler.obj
 0001:00002bd4       ??0bad_alloc@std@@QEAA@AEBV01@@Z 0000000140003bd4 f i libcpmt:xthrow.obj
 0001:00002c14       ??0bad_alloc@std@@QEAA@XZ  0000000140003c14 f i libcpmt:xthrow.obj
 0001:00002c34       ??0exception@std@@QEAA@AEBV01@@Z 0000000140003c34 f i libcpmt:xthrow.obj
 0001:00002c6c       ??0length_error@std@@QEAA@AEBV01@@Z 0000000140003c6c f i libcpmt:xthrow.obj
 0001:00002cac       ??0length_error@std@@QEAA@PEBD@Z 0000000140003cac f i libcpmt:xthrow.obj
 0001:00002cf8       ??0logic_error@std@@QEAA@AEBV01@@Z 0000000140003cf8 f i libcpmt:xthrow.obj
 0001:00002d38       ??1length_error@std@@UEAA@XZ 0000000140003d38 f i libcpmt:xthrow.obj
 0001:00002d38       ??1bad_array_new_length@std@@UEAA@XZ 0000000140003d38 f i LIBCMT:throw_bad_alloc.obj
 0001:00002d38       ??1bad_alloc@std@@UEAA@XZ  0000000140003d38 f i libcpmt:xthrow.obj
 0001:00002d38       ??1bad_exception@std@@UEAA@XZ 0000000140003d38 f i libvcruntime:frame.obj
 0001:00002d4c       ??_Glength_error@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Elength_error@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Ebad_alloc@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Gexception@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Glogic_error@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Gbad_array_new_length@std@@UEAAPEAXI@Z 0000000140003d4c f i LIBCMT:throw_bad_alloc.obj
 0001:00002d4c       ??_Ebad_array_new_length@std@@UEAAPEAXI@Z 0000000140003d4c f i LIBCMT:throw_bad_alloc.obj
 0001:00002d4c       ??_Elogic_error@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Gbad_alloc@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Ebad_exception@std@@UEAAPEAXI@Z 0000000140003d4c f i libvcruntime:frame.obj
 0001:00002d4c       ??_Eexception@std@@UEAAPEAXI@Z 0000000140003d4c f i libcpmt:xthrow.obj
 0001:00002d4c       ??_Gbad_exception@std@@UEAAPEAXI@Z 0000000140003d4c f i libvcruntime:frame.obj
 0001:00002d90       ?_Xlength_error@std@@YAXPEBD@Z 0000000140003d90 f   libcpmt:xthrow.obj
 0001:00002db4       ?what@exception@std@@UEBAPEBDXZ 0000000140003db4 f i libcpmt:xthrow.obj
 0001:00002de0       __security_check_cookie    0000000140003de0 f   LIBCMT:amdsecgs.obj
 0001:00002e04       __raise_securityfailure    0000000140003e04 f   LIBCMT:gs_report.obj
 0001:00002e38       __report_gsfailure         0000000140003e38 f   LIBCMT:gs_report.obj
 0001:00002f0c       __report_rangecheckfailure 0000000140003f0c f   LIBCMT:gs_report.obj
 0001:00002f20       __report_securityfailure   0000000140003f20 f   LIBCMT:gs_report.obj
 0001:000030a0       ??2@YAPEAX_K@Z             00000001400040a0 f   LIBCMT:new_scalar.obj
 0001:000030dc       ??3@YAXPEAX_K@Z            00000001400040dc f   LIBCMT:delete_scalar_size.obj
 0001:0000333c       wWinMainCRTStartup         000000014000433c f   LIBCMT:exe_wwinmain.obj
 0001:00003350       ??_Etype_info@@UEAAPEAXI@Z 0000000140004350 f i LIBCMT:std_type_info_static.obj
 0001:00003350       ??_Gtype_info@@UEAAPEAXI@Z 0000000140004350 f i LIBCMT:std_type_info_static.obj
 0001:0000337c       ??0bad_array_new_length@std@@QEAA@AEBV01@@Z 000000014000437c f i LIBCMT:throw_bad_alloc.obj
 0001:000033bc       ??0bad_array_new_length@std@@QEAA@XZ 00000001400043bc f i LIBCMT:throw_bad_alloc.obj
 0001:000033dc       ?__scrt_throw_std_bad_alloc@@YAXXZ 00000001400043dc f   LIBCMT:throw_bad_alloc.obj
 0001:000033fc       ?__scrt_throw_std_bad_array_new_length@@YAXXZ 00000001400043fc f   LIBCMT:throw_bad_alloc.obj
 0001:0000341c       ??3@YAXPEAX@Z              000000014000441c f   LIBCMT:delete_scalar.obj
 0001:00003424       __scrt_acquire_startup_lock 0000000140004424 f   LIBCMT:utility.obj
 0001:00003460       __scrt_initialize_crt      0000000140004460 f   LIBCMT:utility.obj
 0001:000034ac       __scrt_initialize_onexit_tables 00000001400044ac f   LIBCMT:utility.obj
 0001:00003584       __scrt_is_nonwritable_in_current_image 0000000140004584 f   LIBCMT:utility.obj
 0001:00003620       __scrt_release_startup_lock 0000000140004620 f   LIBCMT:utility.obj
 0001:00003644       __scrt_uninitialize_crt    0000000140004644 f   LIBCMT:utility.obj
 0001:00003670       _onexit                    0000000140004670 f   LIBCMT:utility.obj
 0001:000036c0       atexit                     00000001400046c0 f   LIBCMT:utility.obj
 0001:000036d8       __security_init_cookie     00000001400046d8 f   LIBCMT:gs_support.obj
 0001:00003784       _get_startup_new_mode      0000000140004784 f   LIBCMT:new_mode.obj
 0001:00003784       __scrt_initialize_winrt    0000000140004784 f   LIBCMT:utility_desktop.obj
 0001:00003784       _matherr                   0000000140004784 f   LIBCMT:matherr.obj
 0001:00003784       _get_startup_thread_locale_mode 0000000140004784 f   LIBCMT:thread_locale.obj
 0001:00003784       __scrt_stub_for_initialize_mta 0000000140004784 f   LIBCMT:utility_desktop.obj
 0001:00003784       _get_startup_commit_mode   0000000140004784 f   LIBCMT:commit_mode.obj
 0001:00003784       __scrt_exe_initialize_mta  0000000140004784 f   LIBCMT:utility_desktop.obj
 0001:00003788       _get_startup_argv_mode     0000000140004788 f   LIBCMT:argv_mode.obj
 0001:00003790       _get_startup_file_mode     0000000140004790 f   LIBCMT:file_mode.obj
 0001:00003798       ?__scrt_initialize_type_info@@YAXXZ 0000000140004798 f   LIBCMT:tncleanup.obj
 0001:000037a8       __acrt_uninitialize_command_line 00000001400047a8 f   libucrt:argv_data.obj
 0001:000037a8       _should_initialize_environment 00000001400047a8 f   LIBCMT:env_mode.obj
 0001:000037ac       _initialize_denormal_control 00000001400047ac f   LIBCMT:denormal_control.obj
 0001:000037ac       _initialize_invalid_parameter_handler 00000001400047ac f   LIBCMT:invalid_parameter_handler.obj
 0001:000037ac       _guard_check_icall_nop     00000001400047ac f   LIBCMT:guard_support.obj
 0001:000037b0       __local_stdio_printf_options 00000001400047b0 f i LIBCMT:default_local_stdio_options.obj
 0001:000037b8       __local_stdio_scanf_options 00000001400047b8 f i LIBCMT:default_local_stdio_options.obj
 0001:000037c0       __scrt_initialize_default_local_stdio_options 00000001400047c0 f   LIBCMT:default_local_stdio_options.obj
 0001:000037dc       __scrt_is_user_matherr_present 00000001400047dc f   LIBCMT:matherr_detection.obj
 0001:000037e8       __scrt_get_dyn_tls_init_callback 00000001400047e8 f   LIBCMT:dyn_tls_init.obj
 0001:000037f0       __scrt_get_dyn_tls_dtor_callback 00000001400047f0 f   LIBCMT:dyn_tls_dtor.obj
 0001:000037f8       __crt_debugger_hook        00000001400047f8 f   LIBCMT:utility_desktop.obj
 0001:00003800       __scrt_fastfail            0000000140004800 f   LIBCMT:utility_desktop.obj
 0001:0000394c       __scrt_get_show_window_mode 000000014000494c f   LIBCMT:utility_desktop.obj
 0001:00003988       __scrt_initialize_mta      0000000140004988 f   LIBCMT:utility_desktop.obj
 0001:00003990       __scrt_is_managed_app      0000000140004990 f   LIBCMT:utility_desktop.obj
 0001:000039e4       __scrt_set_unhandled_exception_filter 00000001400049e4 f   LIBCMT:utility_desktop.obj
 0001:000039f4       __scrt_unhandled_exception_filter 00000001400049f4 f   LIBCMT:utility_desktop.obj
 0001:00003a2c       _RTC_Initialize            0000000140004a2c f   LIBCMT:initsect.obj
 0001:00003a68       _RTC_Terminate             0000000140004a68 f   LIBCMT:initsect.obj
 0001:00003aa4       __isa_available_init       0000000140004aa4 f   LIBCMT:cpu_disp.obj
 0001:00003c20       __scrt_is_ucrt_dll_in_use  0000000140004c20 f   LIBCMT:ucrt_detection.obj
 0001:00003c30       ??$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z 0000000140004c30 f i libvcruntime:risctrnsctrl.obj
 0001:00003c84       ?CatchTryBlock@__FrameHandler3@@SAPEBU_s_TryBlockMapEntry@@PEBU_s_FuncInfo@@H@Z 0000000140004c84 f   libvcruntime:risctrnsctrl.obj
 0001:00003cdc       ?ExecutionInCatch@__FrameHandler3@@SA_NPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140004cdc f   libvcruntime:risctrnsctrl.obj
 0001:00003d08       ?FrameUnwindToEmptyState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140004d08 f   libvcruntime:risctrnsctrl.obj
 0001:00003d6c       ?GetEstablisherFrame@__FrameHandler3@@SAPEA_KPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@0@Z 0000000140004d6c f   libvcruntime:risctrnsctrl.obj
 0001:00003e38       ?GetRangeOfTrysToCheck@__FrameHandler3@@SA?AU?$pair@Viterator@TryBlockMap@__FrameHandler3@@V123@@std@@AEAVTryBlockMap@1@HH@Z 0000000140004e38 f   libvcruntime:risctrnsctrl.obj
 0001:00003f94       ?UnwindNestedFrames@__FrameHandler3@@SAXPEA_KPEAUEHExceptionRecord@@PEAU_CONTEXT@@0PEAXPEBU_s_FuncInfo@@HHPEBU_s_HandlerType@@PEAU_xDISPATCHER_CONTEXT@@E@Z 0000000140004f94 f   libvcruntime:risctrnsctrl.obj
 0001:000040b8       _CreateFrameInfo           00000001400050b8 f   libvcruntime:risctrnsctrl.obj
 0001:000040f4       _FindAndUnlinkFrame        00000001400050f4 f   libvcruntime:risctrnsctrl.obj
 0001:00004148       _GetImageBase              0000000140005148 f   libvcruntime:risctrnsctrl.obj
 0001:0000415c       _GetThrowImageBase         000000014000515c f   libvcruntime:risctrnsctrl.obj
 0001:00004170       _SetImageBase              0000000140005170 f   libvcruntime:risctrnsctrl.obj
 0001:00004188       _SetThrowImageBase         0000000140005188 f   libvcruntime:risctrnsctrl.obj
 0001:000041a0       __CxxFrameHandler3         00000001400051a0 f   libvcruntime:risctrnsctrl.obj
 0001:00004220       __DestructExceptionObject  0000000140005220 f   libvcruntime:ehhelpers.obj
 0001:00004294       ?_CallMemberFunction0@@YAXQEAX0@Z 0000000140005294 f i libvcruntime:ehhelpers.obj
 0001:00004298       _IsExceptionObjectToBeDestroyed 0000000140005298 f   libvcruntime:ehhelpers.obj
 0001:000042c8       __AdjustPointer            00000001400052c8 f   libvcruntime:ehhelpers.obj
 0001:000042ec       __FrameUnwindFilter        00000001400052ec f   libvcruntime:ehhelpers.obj
 0001:00004338       __std_terminate            0000000140005338 f   libvcruntime:ehhelpers.obj
 0001:00004344       __std_exception_copy       0000000140005344 f   libvcruntime:std_exception.obj
 0001:000043d4       __std_exception_destroy    00000001400053d4 f   libvcruntime:std_exception.obj
 0001:000043fc       _CxxThrowException         00000001400053fc f   libvcruntime:throw.obj
 0001:000044bc       __C_specific_handler       00000001400054bc f   libvcruntime:riscchandler.obj
 0001:000046c8       __vcrt_initialize          00000001400056c8 f   libvcruntime:initialization.obj
 0001:000046fc       __vcrt_uninitialize        00000001400056fc f   libvcruntime:initialization.obj
 0001:0000471c       __std_type_info_compare    000000014000571c f   libvcruntime:std_type_info.obj
 0001:00004760       memset_repmovs             0000000140005760 f   libvcruntime:memset.obj
 0001:00004780       memset                     0000000140005780 f   libvcruntime:memset.obj
 0001:00004910       __vcrt_freefls             0000000140005910 f   libvcruntime:per_thread_data.obj
 0001:00004930       __vcrt_getptd              0000000140005930 f   libvcruntime:per_thread_data.obj
 0001:0000494c       __vcrt_getptd_noexit       000000014000594c f   libvcruntime:per_thread_data.obj
 0001:00004a18       __vcrt_initialize_ptd      0000000140005a18 f   libvcruntime:per_thread_data.obj
 0001:00004a6c       __vcrt_uninitialize_ptd    0000000140005a6c f   libvcruntime:per_thread_data.obj
 0001:00004a90       ?GetCurrentState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140005a90 f   libvcruntime:ehstate.obj
 0001:00004ab8       ?GetUnwindTryBlock@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140005ab8 f   libvcruntime:ehstate.obj
 0001:00004ae4       ?SetState@__FrameHandler3@@SAXPEA_KPEBU_s_FuncInfo@@H@Z 0000000140005ae4 f   libvcruntime:ehstate.obj
 0001:00004af0       ?SetUnwindTryBlock@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 0000000140005af0 f   libvcruntime:ehstate.obj
 0001:00004b2c       ?StateFromControlPc@__FrameHandler3@@SAHPEBU_s_FuncInfo@@PEAU_xDISPATCHER_CONTEXT@@@Z 0000000140005b2c f   libvcruntime:ehstate.obj
 0001:00004b34       ?StateFromIp@__FrameHandler3@@SAHPEBU_s_FuncInfo@@PEAU_xDISPATCHER_CONTEXT@@_K@Z 0000000140005b34 f   libvcruntime:ehstate.obj
 0001:000055c0       ??$TypeMatchHelper@V__FrameHandler3@@@@YAHPEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_ThrowInfo@@@Z 00000001400065c0 f i libvcruntime:frame.obj
 0001:00005704       ??$__InternalCxxFrameHandler@V__FrameHandler3@@@@YA?AW4_EXCEPTION_DISPOSITION@@PEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H1E@Z 0000000140006704 f i libvcruntime:frame.obj
 0001:0000594c       ??0bad_exception@std@@QEAA@AEBV01@@Z 000000014000694c f i libvcruntime:frame.obj
 0001:0000598c       ??0bad_exception@std@@QEAA@XZ 000000014000698c f i libvcruntime:frame.obj
 0001:000059ac       ?CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z 00000001400069ac f   libvcruntime:frame.obj
 0001:00005c20       ?FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 0000000140006c20 f   libvcruntime:frame.obj
 0001:00005db4       ?GetHandlerSearchState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140006db4 f i libvcruntime:frame.obj
 0001:00005fb8       ?_CallMemberFunction1@@YAXQEAX00@Z 0000000140006fb8 f i libvcruntime:frame.obj
 0001:00005fc4       ?_CallMemberFunction2@@YAXQEAX00H@Z 0000000140006fc4 f i libvcruntime:frame.obj
 0001:00005ff0       _NLG_Notify                0000000140006ff0 f   libvcruntime:notify.obj
 0001:00006010       __NLG_Dispatch2            0000000140007010 f   libvcruntime:notify.obj
 0001:00006020       __NLG_Return2              0000000140007020 f   libvcruntime:notify.obj
 0001:00006024       __except_validate_context_record 0000000140007024 f   libvcruntime:jbcxrval.obj
 0001:0000605c       __vcrt_initialize_locks    000000014000705c f   libvcruntime:locks.obj
 0001:000060a4       __vcrt_uninitialize_locks  00000001400070a4 f   libvcruntime:locks.obj
 0001:000062b4       __vcrt_FlsAlloc            00000001400072b4 f   libvcruntime:winapi_downlevel.obj
 0001:000062fc       __vcrt_FlsFree             00000001400072fc f   libvcruntime:winapi_downlevel.obj
 0001:00006344       __vcrt_FlsGetValue         0000000140007344 f   libvcruntime:winapi_downlevel.obj
 0001:0000638c       __vcrt_FlsSetValue         000000014000738c f   libvcruntime:winapi_downlevel.obj
 0001:000063e0       __vcrt_InitializeCriticalSectionEx 00000001400073e0 f   libvcruntime:winapi_downlevel.obj
 0001:00006444       __vcrt_initialize_winapi_thunks 0000000140007444 f   libvcruntime:winapi_downlevel.obj
 0001:00006474       __vcrt_uninitialize_winapi_thunks 0000000140007474 f   libvcruntime:winapi_downlevel.obj
 0001:000064b4       __vcrt_initialize_pure_virtual_call_handler 00000001400074b4 f   libvcruntime:purevirt_data.obj
 0001:000064e0       _CallSettingFrame          00000001400074e0 f   libvcruntime:handlers.obj
 0001:00006530       _CallSettingFrameEncoded   0000000140007530 f   libvcruntime:handlers.obj
 0001:00006590       memcpy_repmovs             0000000140007590 f   libvcruntime:memcpy.obj
 0001:000065b0       memmove                    00000001400075b0 f   libvcruntime:memcpy.obj
 0001:000065b0       memcpy                     00000001400075b0 f   libvcruntime:memcpy.obj
 0001:00006aa4       _wfopen_s                  0000000140007aa4 f   libucrt:fopen.obj
 0001:00006afc       _fclose_nolock             0000000140007afc f   libucrt:fclose.obj
 0001:00006b80       fclose                     0000000140007b80 f   libucrt:fclose.obj
 0001:00006be4       ??0_LocaleUpdate@@QEAA@QEAU__crt_locale_pointers@@@Z 0000000140007be4 f i libucrt:_wctype.obj
 0001:00006c80       _isleadbyte_l              0000000140007c80 f i libucrt:_wctype.obj
 0001:00006ccc       iswcntrl                   0000000140007ccc f i libucrt:_wctype.obj
 0001:00006cd8       iswspace                   0000000140007cd8 f i libucrt:_wctype.obj
 0001:00006dac       fgetws                     0000000140007dac f   libucrt:fgets.obj
 0001:00006db4       __ascii_wcsnicmp           0000000140007db4 f   libucrt:wcsnicmp.obj
 0001:00006e00       _wcsnicmp                  0000000140007e00 f   libucrt:wcsnicmp.obj
 0001:00006e48       _wcsnicmp_l                0000000140007e48 f   libucrt:wcsnicmp.obj
 0001:00006f98       __acrt_call_reportfault    0000000140007f98 f   libucrt:invalid_parameter.obj
 0001:000070f4       __acrt_initialize_invalid_parameter_handler 00000001400080f4 f   libucrt:invalid_parameter.obj
 0001:000070fc       _invalid_parameter         00000001400080fc f   libucrt:invalid_parameter.obj
 0001:000071ac       _invalid_parameter_noinfo  00000001400081ac f   libucrt:invalid_parameter.obj
 0001:000071cc       _invalid_parameter_noinfo_noreturn 00000001400081cc f   libucrt:invalid_parameter.obj
 0001:000071fc       _invoke_watson             00000001400081fc f   libucrt:invalid_parameter.obj
 0001:00007244       wcsncmp                    0000000140008244 f   libucrt:wcsncmp.obj
 0001:00007270       __acrt_initialize_new_handler 0000000140008270 f   libucrt:new_handler.obj
 0001:00007278       _callnewh                  0000000140008278 f   libucrt:new_handler.obj
 0001:000072a8       _query_new_handler         00000001400082a8 f   libucrt:new_handler.obj
 0001:000072dc       malloc                     00000001400082dc f   libucrt:malloc.obj
 0001:000072e4       _seh_filter_exe            00000001400082e4 f   libucrt:exception_filter.obj
 0001:00007468       _query_app_type            0000000140008468 f   libucrt:report_runtime_error.obj
 0001:00007470       _set_app_type              0000000140008470 f   libucrt:report_runtime_error.obj
 0001:00007478       __acrt_has_user_matherr    0000000140008478 f   libucrt:matherr.obj
 0001:00007498       __acrt_initialize_user_matherr 0000000140008498 f   libucrt:matherr.obj
 0001:000074a0       __acrt_invoke_user_matherr 00000001400084a0 f   libucrt:matherr.obj
 0001:000074d0       __setusermatherr           00000001400084d0 f   libucrt:matherr.obj
 0001:0000769c       __acrt_allocate_buffer_for_argv 000000014000869c f   libucrt:argv_parsing.obj
 0001:000076fc       _configure_wide_argv       00000001400086fc f   libucrt:argv_parsing.obj
 0001:00007a78       __dcrt_uninitialize_environments_nolock 0000000140008a78 f   libucrt:environment_initialization.obj
 0001:00007ab0       _initialize_wide_environment 0000000140008ab0 f   libucrt:environment_initialization.obj
 0001:00007ab8       _get_wide_winmain_command_line 0000000140008ab8 f   libucrt:argv_winmain.obj
 0001:00007b0c       _initterm                  0000000140008b0c f   libucrt:initterm.obj
 0001:00007b70       _initterm_e                0000000140008b70 f   libucrt:initterm.obj
 0001:00007e1c       __acrt_initialize_thread_local_exit_callback 0000000140008e1c f   libucrt:exit.obj
 0001:00007e24       _c_exit                    0000000140008e24 f   libucrt:exit.obj
 0001:00007e34       _cexit                     0000000140008e34 f   libucrt:exit.obj
 0001:00007e44       _exit                      0000000140008e44 f   libucrt:exit.obj
 0001:00007e50       _register_thread_local_exe_atexit_callback 0000000140008e50 f   libucrt:exit.obj
 0001:00007e8c       exit                       0000000140008e8c f   libucrt:exit.obj
 0001:00007e98       _get_fmode                 0000000140008e98 f   libucrt:setmode.obj
 0001:00007ec8       _set_fmode                 0000000140008ec8 f   libucrt:setmode.obj
 0001:00007f08       _setmode_nolock            0000000140008f08 f   libucrt:setmode.obj
 0001:00008058       __acrt_set_locale_changed  0000000140009058 f   libucrt:wsetlocale.obj
 0001:00008064       __acrt_uninitialize_locale 0000000140009064 f   libucrt:wsetlocale.obj
 0001:00008094       _configthreadlocale        0000000140009094 f   libucrt:wsetlocale.obj
 0001:00008100       _query_new_mode            0000000140009100 f   libucrt:new_mode.obj
 0001:00008108       _set_new_mode              0000000140009108 f   libucrt:new_mode.obj
 0001:00008134       __p__commode               0000000140009134 f   libucrt:ncommode.obj
 0001:0000813c       free                       000000014000913c f   libucrt:free.obj
 0001:00008490       _crt_atexit                0000000140009490 f   libucrt:onexit.obj
 0001:000084a0       _execute_onexit_table      00000001400094a0 f   libucrt:onexit.obj
 0001:000084dc       _initialize_onexit_table   00000001400094dc f   libucrt:onexit.obj
 0001:00008504       _register_onexit_function  0000000140009504 f   libucrt:onexit.obj
 0001:00008678       __acrt_initialize          0000000140009678 f   libucrt:initialization.obj
 0001:0000868c       __acrt_uninitialize        000000014000968c f   libucrt:initialization.obj
 0001:000086c4       terminate                  00000001400096c4 f   libucrt:terminate.obj
 0001:000086e4       strcpy_s                   00000001400096e4 f   libucrt:strcpy_s.obj
 0001:00008744       abort                      0000000140009744 f   libucrt:abort.obj
 0001:0000879c       calloc                     000000014000979c f   libucrt:calloc.obj
 0001:000087c0       strncmp                    00000001400097c0 f   libucrt:strncmp.obj
 0001:00008840       __acrt_errno_from_os_error 0000000140009840 f   libucrt:errno.obj
 0001:00008888       __acrt_errno_map_os_error  0000000140009888 f   libucrt:errno.obj
 0001:000088d8       __doserrno                 00000001400098d8 f   libucrt:errno.obj
 0001:000088f8       _errno                     00000001400098f8 f   libucrt:errno.obj
 0001:00008918       __acrt_initialize_stdio    0000000140009918 f   libucrt:_file.obj
 0001:00008a38       __acrt_uninitialize_stdio  0000000140009a38 f   libucrt:_file.obj
 0001:00008a94       _lock_file                 0000000140009a94 f   libucrt:_file.obj
 0001:00008aa0       _unlock_file               0000000140009aa0 f   libucrt:_file.obj
 0001:00008aac       ?__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ 0000000140009aac f   libucrt:stream.obj
 0001:00008b04       ?__acrt_stdio_free_stream@@YAXV__crt_stdio_stream@@@Z 0000000140009b04 f   libucrt:stream.obj
 0001:00008c0c       ??$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z 0000000140009c0c f i libucrt:openfile.obj
 0001:00008f0c       _wopenfile                 0000000140009f0c f   libucrt:openfile.obj
 0001:00008fa8       _free_base                 0000000140009fa8 f   libucrt:free_base.obj
 0001:0000905c       _close                     000000014000a05c f   libucrt:close.obj
 0001:00009100       _close_nolock              000000014000a100 f   libucrt:close.obj
 0001:000091c0       _fileno                    000000014000a1c0 f   libucrt:fileno.obj
 0001:000091e8       __acrt_stdio_free_buffer_nolock 000000014000a1e8 f   libucrt:_freebuf.obj
 0001:00009404       __acrt_stdio_flush_nolock  000000014000a404 f   libucrt:fflush.obj
 0001:00009480       _fflush_nolock             000000014000a480 f   libucrt:fflush.obj
 0001:000094cc       _flushall                  000000014000a4cc f   libucrt:fflush.obj
 0001:000094d4       iswctype                   000000014000a4d4 f   libucrt:iswctype.obj
 0001:000098bc       __acrt_getptd              000000014000a8bc f   libucrt:per_thread_data.obj
 0001:00009990       __acrt_getptd_head         000000014000a990 f   libucrt:per_thread_data.obj
 0001:00009a38       __acrt_getptd_noexit       000000014000aa38 f   libucrt:per_thread_data.obj
 0001:00009b04       __acrt_initialize_ptd      000000014000ab04 f   libucrt:per_thread_data.obj
 0001:00009b40       __acrt_uninitialize_ptd    000000014000ab40 f   libucrt:per_thread_data.obj
 0001:00009b64       __acrt_update_locale_info  000000014000ab64 f   libucrt:locale_update.obj
 0001:00009b98       __acrt_update_multibyte_info 000000014000ab98 f   libucrt:locale_update.obj
 0001:00009bcc       _fgetwc_nolock             000000014000abcc f   libucrt:fgetwc.obj
 0001:00009d70       _getwc_nolock              000000014000ad70 f   libucrt:fgetwc.obj
 0001:00009d78       _fgetc_nolock              000000014000ad78 f   libucrt:fgetc.obj
 0001:00009dbc       _getc_nolock               000000014000adbc f   libucrt:fgetc.obj
 0001:00009fc0       __acrt_initialize_lowio    000000014000afc0 f   libucrt:ioinit.obj
 0001:00009ffc       __acrt_uninitialize_lowio  000000014000affc f   libucrt:ioinit.obj
 0001:0000a03c       _towlower_l                000000014000b03c f   libucrt:towlower.obj
 0001:0000a0f8       __pctype_func              000000014000b0f8 f   libucrt:ctype.obj
 0001:0000a128       __acrt_initialize_locks    000000014000b128 f   libucrt:locks.obj
 0001:0000a170       __acrt_lock                000000014000b170 f   libucrt:locks.obj
 0001:0000a18c       __acrt_uninitialize_locks  000000014000b18c f   libucrt:locks.obj
 0001:0000a1c4       __acrt_unlock              000000014000b1c4 f   libucrt:locks.obj
 0001:0000a1e0       _malloc_base               000000014000b1e0 f   libucrt:malloc_base.obj
 0001:0000a240       wcscpy_s                   000000014000b240 f   libucrt:wcscpy_s.obj
 0001:0000a2a8       wcsncpy_s                  000000014000b2a8 f   libucrt:wcsncpy_s.obj
 0001:0000a38c       _calloc_base               000000014000b38c f   libucrt:calloc_base.obj
 0001:0000a970       __acrt_expand_wide_argv_wildcards 000000014000b970 f   libucrt:argv_wildcards.obj
 0001:0000b0a4       __acrt_initialize_multibyte 000000014000c0a4 f   libucrt:mbctype.obj
 0001:0000b104       __acrt_update_thread_multibyte_data 000000014000c104 f   libucrt:mbctype.obj
 0001:0000b120       _setmbcp_nolock            000000014000c120 f   libucrt:mbctype.obj
 0001:0000b3dc       __acrt_initialize_command_line 000000014000c3dc f   libucrt:argv_data.obj
 0001:0000b404       __acrt_MultiByteToWideChar 000000014000c404 f   libucrt:multibytetowidechar.obj
 0001:0000b460       __acrt_WideCharToMultiByte 000000014000c460 f   libucrt:widechartomultibyte.obj
 0001:0000b4f8       __dcrt_get_wide_environment_from_os 000000014000c4f8 f   libucrt:get_environment_from_os.obj
 0001:0000b598       __acrt_get_process_end_policy 000000014000c598 f   libucrt:win_policies.obj
 0001:0000b5d4       __acrt_lowio_create_handle_array 000000014000c5d4 f   libucrt:osfinfo.obj
 0001:0000b67c       __acrt_lowio_destroy_handle_array 000000014000c67c f   libucrt:osfinfo.obj
 0001:0000b6cc       __acrt_lowio_ensure_fh_exists 000000014000c6cc f   libucrt:osfinfo.obj
 0001:0000b774       __acrt_lowio_lock_fh       000000014000c774 f   libucrt:osfinfo.obj
 0001:0000b79c       __acrt_lowio_set_os_handle 000000014000c79c f   libucrt:osfinfo.obj
 0001:0000b85c       __acrt_lowio_unlock_fh     000000014000c85c f   libucrt:osfinfo.obj
 0001:0000b884       _alloc_osfhnd              000000014000c884 f   libucrt:osfinfo.obj
 0001:0000b9c4       _free_osfhnd               000000014000c9c4 f   libucrt:osfinfo.obj
 0001:0000ba80       _get_osfhandle             000000014000ca80 f   libucrt:osfinfo.obj
 0001:0000baf8       __acrt_locale_free_monetary 000000014000caf8 f   libucrt:initmon.obj
 0001:0000bc04       __acrt_locale_free_numeric 000000014000cc04 f   libucrt:initnum.obj
 0001:0000bcc8       __acrt_locale_free_time    000000014000ccc8 f   libucrt:inittime.obj
 0001:0000bdd0       wcsnlen                    000000014000cdd0 f   libucrt:strnlen.obj
 0001:0000bfa8       wcspbrk                    000000014000cfa8 f   libucrt:wcspbrk.obj
 0001:0000bfdc       __acrt_GetStringTypeA      000000014000cfdc f   libucrt:getstringtypea.obj
 0001:0000c16c       __acrt_add_locale_ref      000000014000d16c f   libucrt:locale_refcounting.obj
 0001:0000c1f8       __acrt_free_locale         000000014000d1f8 f   libucrt:locale_refcounting.obj
 0001:0000c370       __acrt_locale_add_lc_time_reference 000000014000d370 f   libucrt:locale_refcounting.obj
 0001:0000c398       __acrt_locale_free_lc_time_if_unreferenced 000000014000d398 f   libucrt:locale_refcounting.obj
 0001:0000c3d0       __acrt_locale_release_lc_time_reference 000000014000d3d0 f   libucrt:locale_refcounting.obj
 0001:0000c3f8       __acrt_release_locale_ref  000000014000d3f8 f   libucrt:locale_refcounting.obj
 0001:0000c4a0       __acrt_update_thread_locale_data 000000014000d4a0 f   libucrt:locale_refcounting.obj
 0001:0000c50c       _updatetlocinfoEx_nolock   000000014000d50c f   libucrt:locale_refcounting.obj
 0001:0000c74c       __acrt_AppPolicyGetProcessTerminationMethodInternal 000000014000d74c f   libucrt:winapi_thunks.obj
 0001:0000c79c       __acrt_FlsAlloc            000000014000d79c f   libucrt:winapi_thunks.obj
 0001:0000c7e4       __acrt_FlsFree             000000014000d7e4 f   libucrt:winapi_thunks.obj
 0001:0000c82c       __acrt_FlsGetValue         000000014000d82c f   libucrt:winapi_thunks.obj
 0001:0000c874       __acrt_FlsSetValue         000000014000d874 f   libucrt:winapi_thunks.obj
 0001:0000c8c8       __acrt_InitializeCriticalSectionEx 000000014000d8c8 f   libucrt:winapi_thunks.obj
 0001:0000c92c       __acrt_LCMapStringEx       000000014000d92c f   libucrt:winapi_thunks.obj
 0001:0000ca08       __acrt_LocaleNameToLCID    000000014000da08 f   libucrt:winapi_thunks.obj
 0001:0000ca58       __acrt_initialize_winapi_thunks 000000014000da58 f   libucrt:winapi_thunks.obj
 0001:0000ca8c       __acrt_uninitialize_winapi_thunks 000000014000da8c f   libucrt:winapi_thunks.obj
 0001:0000cad0       _recalloc_base             000000014000dad0 f   libucrt:recalloc.obj
 0001:0000cb68       __acrt_initialize_heap     000000014000db68 f   libucrt:heap_handle.obj
 0001:0000cb84       __acrt_uninitialize_heap   000000014000db84 f   libucrt:heap_handle.obj
 0001:0000cb90       __acrt_execute_initializers 000000014000db90 f   libucrt:shared_initialization.obj
 0001:0000cc10       __acrt_execute_uninitializers 000000014000dc10 f   libucrt:shared_initialization.obj
 0001:0000cc94       __acrt_get_sigabrt_handler 000000014000dc94 f   libucrt:signal.obj
 0001:0000ccc4       __acrt_initialize_signal_handlers 000000014000dcc4 f   libucrt:signal.obj
 0001:0000cce4       raise                      000000014000dce4 f   libucrt:signal.obj
 0001:0000cf50       _mbtowc_l                  000000014000df50 f   libucrt:mbtowc.obj
 0001:0000d0d0       mbtowc                     000000014000e0d0 f   libucrt:mbtowc.obj
 0001:0000d0d8       _fcloseall                 000000014000e0d8 f   libucrt:closeall.obj
 0001:0000d7b4       _wsopen_nolock             000000014000e7b4 f   libucrt:open.obj
 0001:0000db9c       _wsopen_s                  000000014000eb9c f   libucrt:open.obj
 0001:0000dc5c       _commit                    000000014000ec5c f   libucrt:commit.obj
 0001:0000e550       _write                     000000014000f550 f   libucrt:write.obj
 0001:0000e63c       _write_nolock              000000014000f63c f   libucrt:write.obj
 0001:0000e918       __acrt_GetStringTypeW      000000014000f918 f   libucrt:getstringtypew.obj
 0001:0000e920       _ungetc_nolock             000000014000f920 f   libucrt:ungetc.obj
 0001:0000ea48       ungetc                     000000014000fa48 f   libucrt:ungetc.obj
 0001:0000ec44       __acrt_stdio_refill_and_read_narrow_nolock 000000014000fc44 f   libucrt:_filbuf.obj
 0001:0000edb0       __acrt_stdio_refill_and_read_wide_nolock 000000014000fdb0 f   libucrt:_filbuf.obj
 0001:0000edb8       __acrt_LCMapStringW        000000014000fdb8 f   libucrt:lcmapstringw.obj
 0001:0000ee40       qsort                      000000014000fe40 f   libucrt:qsort.obj
 0001:0000f508       __acrt_LCMapStringA        0000000140010508 f   libucrt:lcmapstringa.obj
 0001:0000f5b8       __acrt_DownlevelLocaleNameToLCID 00000001400105b8 f   libucrt:lcidtoname_downlevel.obj
 0001:0000f668       _msize_base                0000000140010668 f   libucrt:msize.obj
 0001:0000f6a4       _realloc_base              00000001400106a4 f   libucrt:realloc_base.obj
 0001:0000f720       _isatty                    0000000140010720 f   libucrt:isatty.obj
 0001:0000f780       ?__mbrtowc_utf8@__crt_mbstring@@YA_KPEA_WPEBD_KPEAU_Mbstatet@@@Z 0000000140010780 f   libucrt:mbrtowc.obj
 0001:0000f7bc       ?__mbsrtowcs_utf8@__crt_mbstring@@YA_KPEA_WPEAPEBD_KPEAU_Mbstatet@@@Z 00000001400107bc f   libucrt:mbrtowc.obj
 0001:0000f934       _chsize_nolock             0000000140010934 f   libucrt:chsize.obj
 0001:00010078       _read                      0000000140011078 f   libucrt:read.obj
 0001:00010194       _read_nolock               0000000140011194 f   libucrt:read.obj
 0001:00010688       _lseeki64_nolock           0000000140011688 f   libucrt:lseek.obj
 0001:00010690       _putwch_nolock             0000000140011690 f   libucrt:putwch.obj
 0001:000106cc       __acrt_stdio_allocate_buffer_nolock 00000001400116cc f   libucrt:_getbuf.obj
 0001:00010734       __strncnt                  0000000140011734 f   libucrt:strncnt.obj
 0001:0001074c       ?__mbrtoc32_utf8@__crt_mbstring@@YA_KPEA_UPEBD_KPEAU_Mbstatet@@@Z 000000014001174c f   libucrt:mbrtoc32.obj
 0001:00010930       log10                      0000000140011930 f   libucrt:log10.obj
 0001:00010edc       __dcrt_lowio_ensure_console_output_initialized 0000000140011edc f   libucrt:initcon.obj
 0001:00010f30       __dcrt_terminate_console_output 0000000140011f30 f   libucrt:initcon.obj
 0001:00010f4c       __dcrt_write_console       0000000140011f4c f   libucrt:initcon.obj
 0001:00011130       _handle_error              0000000140012130 f   libucrt:libm_error.obj
 0001:00011260       __acrt_initialize_fma3     0000000140012260 f   libucrt:fma3_available.obj
 0001:000112d0       _log10_special             00000001400122d0 f   libucrt:log_special.obj
 0001:000113a0       _get_fpsr                  00000001400123a0 f   libucrt:fpsr.obj
 0001:000113b0       _set_fpsr                  00000001400123b0 f   libucrt:fpsr.obj
 0001:000113ba       _fclrf                     00000001400123ba f   libucrt:fpsr.obj
 0001:000113ce       _frnd                      00000001400123ce f   libucrt:fpsr.obj
 0001:000113f0       _raise_exc                 00000001400123f0 f   libucrt:fpexcept.obj
 0001:00011418       _raise_exc_ex              0000000140012418 f   libucrt:fpexcept.obj
 0001:00011728       _set_errno_from_matherr    0000000140012728 f   libucrt:fpexcept.obj
 0001:00011758       _clrfp                     0000000140012758 f   libucrt:fpctrl.obj
 0001:00011778       _ctrlfp                    0000000140012778 f   libucrt:fpctrl.obj
 0001:000117f4       _set_statfp                00000001400127f4 f   libucrt:fpctrl.obj
 0001:00011814       _statfp                    0000000140012814 f   libucrt:fpctrl.obj
 0001:00011825       IsProcessorFeaturePresent  0000000140012825 f   kernel32:KERNEL32.dll
 0001:0001182c       __GSHandlerCheck           000000014001282c f   LIBCMT:gshandler.obj
 0001:0001184c       __GSHandlerCheckCommon     000000014001284c f   LIBCMT:gshandler.obj
 0001:000118b0       _FindPESection             00000001400128b0 f   LIBCMT:pesect.obj
 0001:00011900       _IsNonwritableInCurrentImage 0000000140012900 f   LIBCMT:pesect.obj
 0001:00011950       _ValidateImageBase         0000000140012950 f   LIBCMT:pesect.obj
 0001:00011990       __chkstk                   0000000140012990 f   LIBCMT:chkstk.obj
 0001:00011990       _alloca_probe              0000000140012990 f   LIBCMT:chkstk.obj
 0001:00011a00       memcmp                     0000000140012a00 f   libvcruntime:memcmp.obj
 0001:00011ac8       __GSHandlerCheck_EH        0000000140012ac8 f   LIBCMT:gshandlereh.obj
 0001:00011b60       _guard_dispatch_icall_nop  0000000140012b60 f   LIBCMT:guard_dispatch.obj
 0002:00000000       __imp_RegCloseKey          0000000140014000     advapi32:ADVAPI32.dll
 0002:00000008       __imp_RegDeleteTreeW       0000000140014008     advapi32:ADVAPI32.dll
 0002:00000010       __imp_RegOpenKeyExW        0000000140014010     advapi32:ADVAPI32.dll
 0002:00000018       __imp_RegGetValueW         0000000140014018     advapi32:ADVAPI32.dll
 0002:00000020       __imp_RegSetKeyValueW      0000000140014020     advapi32:ADVAPI32.dll
 0002:00000028       \177ADVAPI32_NULL_THUNK_DATA 0000000140014028     advapi32:ADVAPI32.dll
 0002:00000030       __imp_LocalFree            0000000140014030     kernel32:KERNEL32.dll
 0002:00000038       __imp_WriteConsoleW        0000000140014038     kernel32:KERNEL32.dll
 0002:00000040       __imp_ReadConsoleW         0000000140014040     kernel32:KERNEL32.dll
 0002:00000048       __imp_ReadFile             0000000140014048     kernel32:KERNEL32.dll
 0002:00000050       __imp_SetEndOfFile         0000000140014050     kernel32:KERNEL32.dll
 0002:00000058       __imp_SetFilePointerEx     0000000140014058     kernel32:KERNEL32.dll
 0002:00000060       __imp_CloseHandle          0000000140014060     kernel32:KERNEL32.dll
 0002:00000068       __imp_HeapSize             0000000140014068     kernel32:KERNEL32.dll
 0002:00000070       __imp_GetConsoleMode       0000000140014070     kernel32:KERNEL32.dll
 0002:00000078       __imp_GetConsoleCP         0000000140014078     kernel32:KERNEL32.dll
 0002:00000080       __imp_FlushFileBuffers     0000000140014080     kernel32:KERNEL32.dll
 0002:00000088       __imp_CreateFileW          0000000140014088     kernel32:KERNEL32.dll
 0002:00000090       __imp_GetProcessHeap       0000000140014090     kernel32:KERNEL32.dll
 0002:00000098       __imp_OutputDebugStringW   0000000140014098     kernel32:KERNEL32.dll
 0002:000000a0       __imp_GetLastError         00000001400140a0     kernel32:KERNEL32.dll
 0002:000000a8       __imp_FormatMessageW       00000001400140a8     kernel32:KERNEL32.dll
 0002:000000b0       __imp_GetProcessId         00000001400140b0     kernel32:KERNEL32.dll
 0002:000000b8       __imp_HeapReAlloc          00000001400140b8     kernel32:KERNEL32.dll
 0002:000000c0       __imp_GetModuleFileNameW   00000001400140c0     kernel32:KERNEL32.dll
 0002:000000c8       __imp_LCMapStringW         00000001400140c8     kernel32:KERNEL32.dll
 0002:000000d0       __imp_RtlCaptureContext    00000001400140d0     kernel32:KERNEL32.dll
 0002:000000d8       __imp_RtlLookupFunctionEntry 00000001400140d8     kernel32:KERNEL32.dll
 0002:000000e0       __imp_RtlVirtualUnwind     00000001400140e0     kernel32:KERNEL32.dll
 0002:000000e8       __imp_UnhandledExceptionFilter 00000001400140e8     kernel32:KERNEL32.dll
 0002:000000f0       __imp_SetUnhandledExceptionFilter 00000001400140f0     kernel32:KERNEL32.dll
 0002:000000f8       __imp_GetCurrentProcess    00000001400140f8     kernel32:KERNEL32.dll
 0002:00000100       __imp_TerminateProcess     0000000140014100     kernel32:KERNEL32.dll
 0002:00000108       __imp_IsProcessorFeaturePresent 0000000140014108     kernel32:KERNEL32.dll
 0002:00000110       __imp_QueryPerformanceCounter 0000000140014110     kernel32:KERNEL32.dll
 0002:00000118       __imp_GetCurrentProcessId  0000000140014118     kernel32:KERNEL32.dll
 0002:00000120       __imp_GetCurrentThreadId   0000000140014120     kernel32:KERNEL32.dll
 0002:00000128       __imp_GetSystemTimeAsFileTime 0000000140014128     kernel32:KERNEL32.dll
 0002:00000130       __imp_InitializeSListHead  0000000140014130     kernel32:KERNEL32.dll
 0002:00000138       __imp_IsDebuggerPresent    0000000140014138     kernel32:KERNEL32.dll
 0002:00000140       __imp_GetStartupInfoW      0000000140014140     kernel32:KERNEL32.dll
 0002:00000148       __imp_GetModuleHandleW     0000000140014148     kernel32:KERNEL32.dll
 0002:00000150       __imp_RtlUnwindEx          0000000140014150     kernel32:KERNEL32.dll
 0002:00000158       __imp_RtlPcToFileHeader    0000000140014158     kernel32:KERNEL32.dll
 0002:00000160       __imp_RaiseException       0000000140014160     kernel32:KERNEL32.dll
 0002:00000168       __imp_SetLastError         0000000140014168     kernel32:KERNEL32.dll
 0002:00000170       __imp_EncodePointer        0000000140014170     kernel32:KERNEL32.dll
 0002:00000178       __imp_EnterCriticalSection 0000000140014178     kernel32:KERNEL32.dll
 0002:00000180       __imp_LeaveCriticalSection 0000000140014180     kernel32:KERNEL32.dll
 0002:00000188       __imp_DeleteCriticalSection 0000000140014188     kernel32:KERNEL32.dll
 0002:00000190       __imp_InitializeCriticalSectionAndSpinCount 0000000140014190     kernel32:KERNEL32.dll
 0002:00000198       __imp_TlsAlloc             0000000140014198     kernel32:KERNEL32.dll
 0002:000001a0       __imp_TlsGetValue          00000001400141a0     kernel32:KERNEL32.dll
 0002:000001a8       __imp_TlsSetValue          00000001400141a8     kernel32:KERNEL32.dll
 0002:000001b0       __imp_TlsFree              00000001400141b0     kernel32:KERNEL32.dll
 0002:000001b8       __imp_FreeLibrary          00000001400141b8     kernel32:KERNEL32.dll
 0002:000001c0       __imp_GetProcAddress       00000001400141c0     kernel32:KERNEL32.dll
 0002:000001c8       __imp_LoadLibraryExW       00000001400141c8     kernel32:KERNEL32.dll
 0002:000001d0       __imp_GetStdHandle         00000001400141d0     kernel32:KERNEL32.dll
 0002:000001d8       __imp_WriteFile            00000001400141d8     kernel32:KERNEL32.dll
 0002:000001e0       __imp_ExitProcess          00000001400141e0     kernel32:KERNEL32.dll
 0002:000001e8       __imp_GetModuleHandleExW   00000001400141e8     kernel32:KERNEL32.dll
 0002:000001f0       __imp_HeapFree             00000001400141f0     kernel32:KERNEL32.dll
 0002:000001f8       __imp_GetFileType          00000001400141f8     kernel32:KERNEL32.dll
 0002:00000200       __imp_HeapAlloc            0000000140014200     kernel32:KERNEL32.dll
 0002:00000208       __imp_FindClose            0000000140014208     kernel32:KERNEL32.dll
 0002:00000210       __imp_FindFirstFileExW     0000000140014210     kernel32:KERNEL32.dll
 0002:00000218       __imp_FindNextFileW        0000000140014218     kernel32:KERNEL32.dll
 0002:00000220       __imp_IsValidCodePage      0000000140014220     kernel32:KERNEL32.dll
 0002:00000228       __imp_GetACP               0000000140014228     kernel32:KERNEL32.dll
 0002:00000230       __imp_GetOEMCP             0000000140014230     kernel32:KERNEL32.dll
 0002:00000238       __imp_GetCPInfo            0000000140014238     kernel32:KERNEL32.dll
 0002:00000240       __imp_GetCommandLineA      0000000140014240     kernel32:KERNEL32.dll
 0002:00000248       __imp_GetCommandLineW      0000000140014248     kernel32:KERNEL32.dll
 0002:00000250       __imp_MultiByteToWideChar  0000000140014250     kernel32:KERNEL32.dll
 0002:00000258       __imp_WideCharToMultiByte  0000000140014258     kernel32:KERNEL32.dll
 0002:00000260       __imp_GetEnvironmentStringsW 0000000140014260     kernel32:KERNEL32.dll
 0002:00000268       __imp_FreeEnvironmentStringsW 0000000140014268     kernel32:KERNEL32.dll
 0002:00000270       __imp_SetStdHandle         0000000140014270     kernel32:KERNEL32.dll
 0002:00000278       __imp_GetStringTypeW       0000000140014278     kernel32:KERNEL32.dll
 0002:00000280       \177KERNEL32_NULL_THUNK_DATA 0000000140014280     kernel32:KERNEL32.dll
 0002:00000288       __imp_ShellExecuteExW      0000000140014288     shell32:SHELL32.dll
 0002:00000290       \177SHELL32_NULL_THUNK_DATA 0000000140014290     shell32:SHELL32.dll
 0002:00000298       __imp_UrlUnescapeW         0000000140014298     shlwapi:SHLWAPI.dll
 0002:000002a0       __imp_PathIsNetworkPathW   00000001400142a0     shlwapi:SHLWAPI.dll
 0002:000002a8       __imp_PathCanonicalizeW    00000001400142a8     shlwapi:SHLWAPI.dll
 0002:000002b0       \177SHLWAPI_NULL_THUNK_DATA 00000001400142b0     shlwapi:SHLWAPI.dll
 0002:000002b8       __imp_AllowSetForegroundWindow 00000001400142b8     user32:USER32.dll
 0002:000002c0       __imp_MessageBoxW          00000001400142c0     user32:USER32.dll
 0002:000002c8       __imp_GetWindowThreadProcessId 00000001400142c8     user32:USER32.dll
 0002:000002d0       __imp_EndDialog            00000001400142d0     user32:USER32.dll
 0002:000002d8       __imp_LoadStringW          00000001400142d8     user32:USER32.dll
 0002:000002e0       __imp_SetDlgItemTextW      00000001400142e0     user32:USER32.dll
 0002:000002e8       __imp_EnumWindows          00000001400142e8     user32:USER32.dll
 0002:000002f0       __imp_BringWindowToTop     00000001400142f0     user32:USER32.dll
 0002:000002f8       __imp_GetDlgItem           00000001400142f8     user32:USER32.dll
 0002:00000300       __imp_DialogBoxParamW      0000000140014300     user32:USER32.dll
 0002:00000308       __imp_EnableWindow         0000000140014308     user32:USER32.dll
 0002:00000310       __imp_WaitForInputIdle     0000000140014310     user32:USER32.dll
 0002:00000318       \177USER32_NULL_THUNK_DATA 0000000140014318     user32:USER32.dll
 0002:00000320       __guard_check_icall_fptr   0000000140014320     LIBCMT:guard_support.obj
 0002:00000328       __guard_dispatch_icall_fptr 0000000140014328     LIBCMT:guard_support.obj
 0002:00000330       __xc_a                     0000000140014330     LIBCMT:initializers.obj
 0002:00000340       __xc_z                     0000000140014340     LIBCMT:initializers.obj
 0002:00000348       __xi_a                     0000000140014348     LIBCMT:initializers.obj
 0002:00000360       __acrt_stdio_initializer   0000000140014360     libucrt:stdio_initializer.obj
 0002:00000368       __acrt_multibyte_initializer 0000000140014368     libucrt:multibyte_initializer.obj
 0002:00000370       __acrt_tran_fma3_initializer 0000000140014370     libucrt:fma3_initializer.obj
 0002:00000378       __xi_z                     0000000140014378     LIBCMT:initializers.obj
 0002:00000380       __xp_a                     0000000140014380     LIBCMT:initializers.obj
 0002:00000388       __acrt_locale_terminator   0000000140014388     libucrt:locale_initializer.obj
 0002:00000390       __dcrt_console_output_terminator 0000000140014390     libucrt:console_output_initializer.obj
 0002:00000398       __acrt_stdio_terminator    0000000140014398     libucrt:stdio_initializer.obj
 0002:000003a0       __xp_z                     00000001400143a0     LIBCMT:initializers.obj
 0002:000003a8       __xt_a                     00000001400143a8     LIBCMT:initializers.obj
 0002:000003b0       __xt_z                     00000001400143b0     LIBCMT:initializers.obj
 0002:000003c8       ??_7exception@std@@6B@     00000001400143c8     libcpmt:xthrow.obj
 0002:000003d8       ??_C@_0BC@EOODALEL@Unknown?5exception@ 00000001400143d8     libcpmt:xthrow.obj
 0002:000003f8       ??_7bad_alloc@std@@6B@     00000001400143f8     libcpmt:xthrow.obj
 0002:00000408       ??_C@_0P@GHFPNOJB@bad?5allocation@ 0000000140014408     libcpmt:xthrow.obj
 0002:00000420       ??_7logic_error@std@@6B@   0000000140014420     libcpmt:xthrow.obj
 0002:00000438       ??_7length_error@std@@6B@  0000000140014438     libcpmt:xthrow.obj
 0002:00000460       ??_7type_info@@6B@         0000000140014460     LIBCMT:std_type_info_static.obj
 0002:00000470       ??_7bad_array_new_length@std@@6B@ 0000000140014470     LIBCMT:throw_bad_alloc.obj
 0002:00000480       ??_C@_0BF@KINCDENJ@bad?5array?5new?5length@ 0000000140014480     LIBCMT:throw_bad_alloc.obj
 0002:00000538       _pDestructExceptionObject  0000000140014538     libvcruntime:ehhelpers.obj
 0002:00000588       ??_7bad_exception@std@@6B@ 0000000140014588     libvcruntime:frame.obj
 0002:00000598       ??_C@_0O@DPKOEFFH@bad?5exception@ 0000000140014598     libvcruntime:frame.obj
 0002:000005c0       ??_C@_1DM@KHCHBNEB@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 00000001400145c0     libvcruntime:winapi_downlevel.obj
 0002:00000600       ??_C@_1DK@LPPGFMPP@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140014600     libvcruntime:winapi_downlevel.obj
 0002:00000640       ??_C@_1BC@GDMECMAK@?$AAk?$AAe?$AAr?$AAn?$AAe?$AAl?$AA3?$AA2@ 0000000140014640     libvcruntime:winapi_downlevel.obj
 0002:00000658       ??_C@_1BA@PFFKHIOG@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9@ 0000000140014658     libvcruntime:winapi_downlevel.obj
 0002:00000668       ??_C@_1BA@IAIFMGEF@?$AAe?$AAx?$AAt?$AA?9?$AAm?$AAs?$AA?9@ 0000000140014668     libvcruntime:winapi_downlevel.obj
 0002:00000680       ??_C@_08KNHFBNJ@FlsAlloc@  0000000140014680     libvcruntime:winapi_downlevel.obj
 0002:00000698       ??_C@_07PEJMOBNF@FlsFree@  0000000140014698     libvcruntime:winapi_downlevel.obj
 0002:000006a8       ??_C@_0M@GDNOONDI@FlsGetValue@ 00000001400146a8     libvcruntime:winapi_downlevel.obj
 0002:000006c0       ??_C@_0M@JCPCPOEF@FlsSetValue@ 00000001400146c0     libvcruntime:winapi_downlevel.obj
 0002:000006d8       ??_C@_0BM@HCFOFFN@InitializeCriticalSectionEx@ 00000001400146d8     libvcruntime:winapi_downlevel.obj
 0002:00000a38       ??_C@_08EHJDFFNH@__based?$CI@ 0000000140014a38     libvcruntime:undname.obj
 0002:00000a48       ??_C@_07KOLFKCDI@__cdecl@  0000000140014a48     libvcruntime:undname.obj
 0002:00000a50       ??_C@_08GHMPAG@__pascal@   0000000140014a50     libvcruntime:undname.obj
 0002:00000a60       ??_C@_09IFJBGAPI@__stdcall@ 0000000140014a60     libvcruntime:undname.obj
 0002:00000a70       ??_C@_0L@NPHFGOKO@__thiscall@ 0000000140014a70     libvcruntime:undname.obj
 0002:00000a80       ??_C@_0L@JMKHOMEK@__fastcall@ 0000000140014a80     libvcruntime:undname.obj
 0002:00000a90       ??_C@_0N@BCKKPABJ@__vectorcall@ 0000000140014a90     libvcruntime:undname.obj
 0002:00000aa0       ??_C@_09HIJEGCPM@__clrcall@ 0000000140014aa0     libvcruntime:undname.obj
 0002:00000aac       ??_C@_06GHPCKEAG@__eabi@   0000000140014aac     libvcruntime:undname.obj
 0002:00000ab8       ??_C@_09IOPIDJLG@__swift_1@ 0000000140014ab8     libvcruntime:undname.obj
 0002:00000ac8       ??_C@_09KFNFGKHF@__swift_2@ 0000000140014ac8     libvcruntime:undname.obj
 0002:00000ad8       ??_C@_07JOMMBBKO@__ptr64@  0000000140014ad8     libvcruntime:undname.obj
 0002:00000ae0       ??_C@_0L@PILCLIHE@__restrict@ 0000000140014ae0     libvcruntime:undname.obj
 0002:00000af0       ??_C@_0M@GFIIJFMG@__unaligned@ 0000000140014af0     libvcruntime:undname.obj
 0002:00000b00       ??_C@_09DHDLOLLB@restrict?$CI@ 0000000140014b00     libvcruntime:undname.obj
 0002:00000b0a       ??_C@_00CNPNBAHC@@         0000000140014b0a     libvcruntime:undname.obj
 0002:00000b0c       ??_C@_04NIHEBCM@?5new@     0000000140014b0c     libvcruntime:undname.obj
 0002:00000b18       ??_C@_07FPCDHGMM@?5delete@ 0000000140014b18     libvcruntime:undname.obj
 0002:00000b20       ??_C@_01NEMOKFLO@?$DN@     0000000140014b20     libvcruntime:undname.obj
 0002:00000b24       ??_C@_02GPIOPFAK@?$DO?$DO@ 0000000140014b24     libvcruntime:undname.obj
 0002:00000b28       ??_C@_02FODMEDOG@?$DM?$DM@ 0000000140014b28     libvcruntime:undname.obj
 0002:00000b2c       ??_C@_01DCLJPIOD@?$CB@     0000000140014b2c     libvcruntime:undname.obj
 0002:00000b30       ??_C@_02EGOFBIJA@?$DN?$DN@ 0000000140014b30     libvcruntime:undname.obj
 0002:00000b34       ??_C@_02FDNJECIE@?$CB?$DN@ 0000000140014b34     libvcruntime:undname.obj
 0002:00000b38       ??_C@_02GPECMEKF@?$FL?$FN@ 0000000140014b38     libvcruntime:undname.obj
 0002:00000b40       ??_C@_08LHJFAFGD@operator@ 0000000140014b40     libvcruntime:undname.obj
 0002:00000b4c       ??_C@_02HBOOOICD@?9?$DO@   0000000140014b4c     libvcruntime:undname.obj
 0002:00000b50       ??_C@_01NBENCBCI@?$CK@     0000000140014b50     libvcruntime:undname.obj
 0002:00000b54       ??_C@_02ECNGHCIF@?$CL?$CL@ 0000000140014b54     libvcruntime:undname.obj
 0002:00000b58       ??_C@_02BAABKJLB@?9?9@     0000000140014b58     libvcruntime:undname.obj
 0002:00000b5c       ??_C@_01JOAMLHOP@?9@       0000000140014b5c     libvcruntime:undname.obj
 0002:00000b60       ??_C@_01MIFGBAGJ@?$CL@     0000000140014b60     libvcruntime:undname.obj
 0002:00000b64       ??_C@_01HNPIGOCE@?$CG@     0000000140014b64     libvcruntime:undname.obj
 0002:00000b68       ??_C@_03MNHNFDLC@?9?$DO?$CK@ 0000000140014b68     libvcruntime:undname.obj
 0002:00000b6c       ??_C@_01KMDKNFGN@?1@       0000000140014b6c     libvcruntime:undname.obj
 0002:00000b70       ??_C@_01FGNFDNOH@?$CF@     0000000140014b70     libvcruntime:undname.obj
 0002:00000b74       ??_C@_01MNNFJEPP@?$DM@     0000000140014b74     libvcruntime:undname.obj
 0002:00000b78       ??_C@_02EHCHHCKH@?$DM?$DN@ 0000000140014b78     libvcruntime:undname.obj
 0002:00000b7c       ??_C@_01PPODPGHN@?$DO@     0000000140014b7c     libvcruntime:undname.obj
 0002:00000b80       ??_C@_02EEKDKGMJ@?$DO?$DN@ 0000000140014b80     libvcruntime:undname.obj
 0002:00000b84       ??_C@_01IHBHIGKO@?0@       0000000140014b84     libvcruntime:undname.obj
 0002:00000b88       ??_C@_02HCKGKOFO@?$CI?$CJ@ 0000000140014b88     libvcruntime:undname.obj
 0002:00000b8c       ??_C@_01PJKLJHI@?$HO@      0000000140014b8c     libvcruntime:undname.obj
 0002:00000b90       ??_C@_01JKBOJNNK@?$FO@     0000000140014b90     libvcruntime:undname.obj
 0002:00000b94       ??_C@_01DNKMNLPK@?$HM@     0000000140014b94     libvcruntime:undname.obj
 0002:00000b98       ??_C@_02PPKAJPJL@?$CG?$CG@ 0000000140014b98     libvcruntime:undname.obj
 0002:00000b9c       ??_C@_02NONPIBCD@?$HM?$HM@ 0000000140014b9c     libvcruntime:undname.obj
 0002:00000ba0       ??_C@_02FPIMKNGF@?$CK?$DN@ 0000000140014ba0     libvcruntime:undname.obj
 0002:00000ba4       ??_C@_02FOEOMHFC@?$CL?$DN@ 0000000140014ba4     libvcruntime:undname.obj
 0002:00000ba8       ??_C@_02FKMDLLOA@?9?$DN@   0000000140014ba8     libvcruntime:undname.obj
 0002:00000bac       ??_C@_02FJEHGPIO@?1?$DN@   0000000140014bac     libvcruntime:undname.obj
 0002:00000bb0       ??_C@_02FENAOKFI@?$CF?$DN@ 0000000140014bb0     libvcruntime:undname.obj
 0002:00000bb4       ??_C@_03IKFCCPFF@?$DO?$DO?$DN@ 0000000140014bb4     libvcruntime:undname.obj
 0002:00000bb8       ??_C@_03CDNPDDLA@?$DM?$DM?$DN@ 0000000140014bb8     libvcruntime:undname.obj
 0002:00000bbc       ??_C@_02FGJGFEAB@?$CG?$DN@ 0000000140014bbc     libvcruntime:undname.obj
 0002:00000bc0       ??_C@_02DHLNPPGH@?$HM?$DN@ 0000000140014bc0     libvcruntime:undname.obj
 0002:00000bc4       ??_C@_02MHEGNOJ@?$FO?$DN@  0000000140014bc4     libvcruntime:undname.obj
 0002:00000bc8       ??_C@_09IFPLHPGF@?$GAvftable?8@ 0000000140014bc8     libvcruntime:undname.obj
 0002:00000bd8       ??_C@_09BLBHBJP@?$GAvbtable?8@ 0000000140014bd8     libvcruntime:undname.obj
 0002:00000be8       ??_C@_07FEEIOKP@?$GAvcall?8@ 0000000140014be8     libvcruntime:undname.obj
 0002:00000bf0       ??_C@_08LLFFHHDJ@?$GAtypeof?8@ 0000000140014bf0     libvcruntime:undname.obj
 0002:00000c00       ??_C@_0BF@KDPPACIK@?$GAlocal?5static?5guard?8@ 0000000140014c00     libvcruntime:undname.obj
 0002:00000c18       ??_C@_08OBABFOLI@?$GAstring?8@ 0000000140014c18     libvcruntime:undname.obj
 0002:00000c28       ??_C@_0BD@JDLKDPAB@?$GAvbase?5destructor?8@ 0000000140014c28     libvcruntime:undname.obj
 0002:00000c40       ??_C@_0BN@DEGPLNFK@?$GAvector?5deleting?5destructor?8@ 0000000140014c40     libvcruntime:undname.obj
 0002:00000c60       ??_C@_0BO@OBMKPJIG@?$GAdefault?5constructor?5closure?8@ 0000000140014c60     libvcruntime:undname.obj
 0002:00000c80       ??_C@_0BN@IMDCHIKM@?$GAscalar?5deleting?5destructor?8@ 0000000140014c80     libvcruntime:undname.obj
 0002:00000ca0       ??_C@_0BO@PFGOCPJJ@?$GAvector?5constructor?5iterator?8@ 0000000140014ca0     libvcruntime:undname.obj
 0002:00000cc0       ??_C@_0BN@LFPFMEDL@?$GAvector?5destructor?5iterator?8@ 0000000140014cc0     libvcruntime:undname.obj
 0002:00000ce0       ??_C@_0CE@IKBNEHA@?$GAvector?5vbase?5constructor?5itera@ 0000000140014ce0     libvcruntime:undname.obj
 0002:00000d08       ??_C@_0BL@NILFHHPC@?$GAvirtual?5displacement?5map?8@ 0000000140014d08     libvcruntime:undname.obj
 0002:00000d28       ??_C@_0CB@JONCMFFK@?$GAeh?5vector?5constructor?5iterator@ 0000000140014d28     libvcruntime:undname.obj
 0002:00000d50       ??_C@_0CA@GCEOPDGL@?$GAeh?5vector?5destructor?5iterator?8@ 0000000140014d50     libvcruntime:undname.obj
 0002:00000d70       ??_C@_0CH@OOJPLCPH@?$GAeh?5vector?5vbase?5constructor?5it@ 0000000140014d70     libvcruntime:undname.obj
 0002:00000d98       ??_C@_0BL@LLKPOHJI@?$GAcopy?5constructor?5closure?8@ 0000000140014d98     libvcruntime:undname.obj
 0002:00000db8       ??_C@_0BA@KBCDOMBN@?$GAudt?5returning?8@ 0000000140014db8     libvcruntime:undname.obj
 0002:00000dc8       ??_C@_03KLGMFNMG@?$GAEH@   0000000140014dc8     libvcruntime:undname.obj
 0002:00000dcc       ??_C@_05KHLCHHI@?$GARTTI@  0000000140014dcc     libvcruntime:undname.obj
 0002:00000dd8       ??_C@_0BA@KKLDJDLB@?$GAlocal?5vftable?8@ 0000000140014dd8     libvcruntime:undname.obj
 0002:00000de8       ??_C@_0CE@IIHCMGGL@?$GAlocal?5vftable?5constructor?5clos@ 0000000140014de8     libvcruntime:undname.obj
 0002:00000e0c       ??_C@_06FHBGPFGH@?5new?$FL?$FN@ 0000000140014e0c     libvcruntime:undname.obj
 0002:00000e18       ??_C@_09LBNFPBCA@?5delete?$FL?$FN@ 0000000140014e18     libvcruntime:undname.obj
 0002:00000e28       ??_C@_0P@HJKNJFNN@?$GAomni?5callsig?8@ 0000000140014e28     libvcruntime:undname.obj
 0002:00000e38       ??_C@_0BL@CNOONJFP@?$GAplacement?5delete?5closure?8@ 0000000140014e38     libvcruntime:undname.obj
 0002:00000e58       ??_C@_0BN@CKNJLHMB@?$GAplacement?5delete?$FL?$FN?5closure?8@ 0000000140014e58     libvcruntime:undname.obj
 0002:00000e78       ??_C@_0CG@CFDHKGGD@?$GAmanaged?5vector?5constructor?5ite@ 0000000140014e78     libvcruntime:undname.obj
 0002:00000ea0       ??_C@_0CF@IMGKMJNO@?$GAmanaged?5vector?5destructor?5iter@ 0000000140014ea0     libvcruntime:undname.obj
 0002:00000ec8       ??_C@_0CG@HLDDJMAG@?$GAeh?5vector?5copy?5constructor?5ite@ 0000000140014ec8     libvcruntime:undname.obj
 0002:00000ef0       ??_C@_0CM@FCBBDIGB@?$GAeh?5vector?5vbase?5copy?5construct@ 0000000140014ef0     libvcruntime:undname.obj
 0002:00000f20       ??_C@_0BL@CLIPGLGB@?$GAdynamic?5initializer?5for?5?8@ 0000000140014f20     libvcruntime:undname.obj
 0002:00000f40       ??_C@_0CB@PDBIFEP@?$GAdynamic?5atexit?5destructor?5for?5@ 0000000140014f40     libvcruntime:undname.obj
 0002:00000f68       ??_C@_0CD@CGAJBKEJ@?$GAvector?5copy?5constructor?5iterat@ 0000000140014f68     libvcruntime:undname.obj
 0002:00000f90       ??_C@_0CJ@GJELGAMM@?$GAvector?5vbase?5copy?5constructor?5@ 0000000140014f90     libvcruntime:undname.obj
 0002:00000fc0       ??_C@_0CL@FGIJHLCE@?$GAmanaged?5vector?5copy?5constructo@ 0000000140014fc0     libvcruntime:undname.obj
 0002:00000ff0       ??_C@_0BM@PMGGMLDN@?$GAlocal?5static?5thread?5guard?8@ 0000000140014ff0     libvcruntime:undname.obj
 0002:00001010       ??_C@_0N@BDNMDMOL@operator?5?$CC?$CC?5@ 0000000140015010     libvcruntime:undname.obj
 0002:00001020       ??_C@_0BC@GGEBGALA@operator?5co_await@ 0000000140015020     libvcruntime:undname.obj
 0002:00001038       ??_C@_0BC@DAFEJGAK@?5Type?5Descriptor?8@ 0000000140015038     libvcruntime:undname.obj
 0002:00001050       ??_C@_0BM@LDKODKLH@?5Base?5Class?5Descriptor?5at?5?$CI@ 0000000140015050     libvcruntime:undname.obj
 0002:00001070       ??_C@_0BD@LGICGFMM@?5Base?5Class?5Array?8@ 0000000140015070     libvcruntime:undname.obj
 0002:00001088       ??_C@_0BN@MECKDCOJ@?5Class?5Hierarchy?5Descriptor?8@ 0000000140015088     libvcruntime:undname.obj
 0002:000010a8       ??_C@_0BK@CFCOFLF@?5Complete?5Object?5Locator?8@ 00000001400150a8     libvcruntime:undname.obj
 0002:000010d0       __acrt_exception_action_table 00000001400150d0     libucrt:exception_filter.obj
 0002:00001190       __acrt_signal_action_table_count 0000000140015190     libucrt:exception_filter.obj
 0002:00001198       __acrt_signal_action_first_fpe_index 0000000140015198     libucrt:exception_filter.obj
 0002:000011a0       __acrt_signal_action_fpe_count 00000001400151a0     libucrt:exception_filter.obj
 0002:000011a8       ??_C@_1BI@BGOHAHKC@?$AAm?$AAs?$AAc?$AAo?$AAr?$AAe?$AAe?$AA?4?$AAd?$AAl?$AAl@ 00000001400151a8     libucrt:exit.obj
 0002:000011c0       ??_C@_0P@MIGLKIOC@CorExitProcess@ 00000001400151c0     libucrt:exit.obj
 0002:00001438       ?ccs@?1???$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z@4QB_WB 0000000140015438     libucrt:openfile.obj
 0002:00001440       ?utf8_encoding@?1???$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z@4QB_WB 0000000140015440     libucrt:openfile.obj
 0002:00001450       ?utf16_encoding@?1???$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z@4QB_WB 0000000140015450     libucrt:openfile.obj
 0002:00001460       ?unicode_encoding@?1???$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z@4QB_WB 0000000140015460     libucrt:openfile.obj
 0002:00001470       __lc_time_c                0000000140015470     libucrt:nlsdata.obj
 0002:00001730       ??_C@_03KOEHGMDN@Sun@      0000000140015730     libucrt:nlsdata.obj
 0002:00001734       ??_C@_03PDAGKDH@Mon@       0000000140015734     libucrt:nlsdata.obj
 0002:00001738       ??_C@_03NAGEINEP@Tue@      0000000140015738     libucrt:nlsdata.obj
 0002:0000173c       ??_C@_03MHOMLAJA@Wed@      000000014001573c     libucrt:nlsdata.obj
 0002:00001740       ??_C@_03IOFIKPDN@Thu@      0000000140015740     libucrt:nlsdata.obj
 0002:00001744       ??_C@_03IDIOELNC@Fri@      0000000140015744     libucrt:nlsdata.obj
 0002:00001748       ??_C@_03FEFJNEK@Sat@       0000000140015748     libucrt:nlsdata.obj
 0002:0000174c       ??_C@_06OOPIFAJ@Sunday@    000000014001574c     libucrt:nlsdata.obj
 0002:00001754       ??_C@_06JLEDEDGH@Monday@   0000000140015754     libucrt:nlsdata.obj
 0002:00001760       ??_C@_07BAAGCFCM@Tuesday@  0000000140015760     libucrt:nlsdata.obj
 0002:00001768       ??_C@_09DLIGFAKA@Wednesday@ 0000000140015768     libucrt:nlsdata.obj
 0002:00001778       ??_C@_08HACCIKIA@Thursday@ 0000000140015778     libucrt:nlsdata.obj
 0002:00001784       ??_C@_06JECMNKMI@Friday@   0000000140015784     libucrt:nlsdata.obj
 0002:00001790       ??_C@_08INBOOONO@Saturday@ 0000000140015790     libucrt:nlsdata.obj
 0002:0000179c       ??_C@_03JIHJHPIE@Jan@      000000014001579c     libucrt:nlsdata.obj
 0002:000017a0       ??_C@_03HJBDCHOM@Feb@      00000001400157a0     libucrt:nlsdata.obj
 0002:000017a4       ??_C@_03ODNJBKGA@Mar@      00000001400157a4     libucrt:nlsdata.obj
 0002:000017a8       ??_C@_03LEOLGMJP@Apr@      00000001400157a8     libucrt:nlsdata.obj
 0002:000017ac       ??_C@_03CNMDKL@May@        00000001400157ac     libucrt:nlsdata.obj
 0002:000017b0       ??_C@_03IDFGHECI@Jun@      00000001400157b0     libucrt:nlsdata.obj
 0002:000017b4       ??_C@_03LBGABGKK@Jul@      00000001400157b4     libucrt:nlsdata.obj
 0002:000017b8       ??_C@_03IFJFEIGA@Aug@      00000001400157b8     libucrt:nlsdata.obj
 0002:000017bc       ??_C@_03GGCAPAJC@Sep@      00000001400157bc     libucrt:nlsdata.obj
 0002:000017c0       ??_C@_03BMAOKBAD@Oct@      00000001400157c0     libucrt:nlsdata.obj
 0002:000017c4       ??_C@_03JPJOFNIA@Nov@      00000001400157c4     libucrt:nlsdata.obj
 0002:000017c8       ??_C@_03MKABNOCG@Dec@      00000001400157c8     libucrt:nlsdata.obj
 0002:000017d0       ??_C@_07CGJPFGJA@January@  00000001400157d0     libucrt:nlsdata.obj
 0002:000017d8       ??_C@_08GNJGEPFN@February@ 00000001400157d8     libucrt:nlsdata.obj
 0002:000017e4       ??_C@_05HPCKOFNC@March@    00000001400157e4     libucrt:nlsdata.obj
 0002:000017ec       ??_C@_05DMJDNLEJ@April@    00000001400157ec     libucrt:nlsdata.obj
 0002:000017f4       ??_C@_04CNLMGBGM@June@     00000001400157f4     libucrt:nlsdata.obj
 0002:000017fc       ??_C@_04MIEPOIFP@July@     00000001400157fc     libucrt:nlsdata.obj
 0002:00001804       ??_C@_06LBBHFDDG@August@   0000000140015804     libucrt:nlsdata.obj
 0002:00001810       ??_C@_09BHHEALKD@September@ 0000000140015810     libucrt:nlsdata.obj
 0002:00001820       ??_C@_07JJNFCEND@October@  0000000140015820     libucrt:nlsdata.obj
 0002:00001828       ??_C@_08HCHEGEOA@November@ 0000000140015828     libucrt:nlsdata.obj
 0002:00001838       ??_C@_08EDHMEBNP@December@ 0000000140015838     libucrt:nlsdata.obj
 0002:00001844       ??_C@_02DEDBPAFC@AM@       0000000140015844     libucrt:nlsdata.obj
 0002:00001848       ??_C@_02CJNFDJBF@PM@       0000000140015848     libucrt:nlsdata.obj
 0002:00001850       ??_C@_08BPBNCDIB@MM?1dd?1yy@ 0000000140015850     libucrt:nlsdata.obj
 0002:00001860       ??_C@_0BE@CKGJFCPC@dddd?0?5MMMM?5dd?0?5yyyy@ 0000000140015860     libucrt:nlsdata.obj
 0002:00001878       ??_C@_08JCCMCCIL@HH?3mm?3ss@ 0000000140015878     libucrt:nlsdata.obj
 0002:00001888       ??_C@_17MBGCMIPB@?$AAS?$AAu?$AAn@ 0000000140015888     libucrt:nlsdata.obj
 0002:00001890       ??_C@_17KBOMKBF@?$AAM?$AAo?$AAn@ 0000000140015890     libucrt:nlsdata.obj
 0002:00001898       ??_C@_17BMKGEGOJ@?$AAT?$AAu?$AAe@ 0000000140015898     libucrt:nlsdata.obj
 0002:000018a0       ??_C@_17CJEDCEPE@?$AAW?$AAe?$AAd@ 00000001400158a0     libucrt:nlsdata.obj
 0002:000018a8       ??_C@_17PDPHAADD@?$AAT?$AAh?$AAu@ 00000001400158a8     libucrt:nlsdata.obj
 0002:000018b0       ??_C@_17HFOLPPLP@?$AAF?$AAr?$AAi@ 00000001400158b0     libucrt:nlsdata.obj
 0002:000018b8       ??_C@_17GGIBDPIH@?$AAS?$AAa?$AAt@ 00000001400158b8     libucrt:nlsdata.obj
 0002:000018c0       ??_C@_1O@IHNHDHPB@?$AAS?$AAu?$AAn?$AAd?$AAa?$AAy@ 00000001400158c0     libucrt:nlsdata.obj
 0002:000018d0       ??_C@_1O@MMNBFLIA@?$AAM?$AAo?$AAn?$AAd?$AAa?$AAy@ 00000001400158d0     libucrt:nlsdata.obj
 0002:000018e0       ??_C@_1BA@ENFBFFEK@?$AAT?$AAu?$AAe?$AAs?$AAd?$AAa?$AAy@ 00000001400158e0     libucrt:nlsdata.obj
 0002:000018f0       ??_C@_1BE@EBOGMDOH@?$AAW?$AAe?$AAd?$AAn?$AAe?$AAs?$AAd?$AAa?$AAy@ 00000001400158f0     libucrt:nlsdata.obj
 0002:00001908       ??_C@_1BC@HHMNLIHE@?$AAT?$AAh?$AAu?$AAr?$AAs?$AAd?$AAa?$AAy@ 0000000140015908     libucrt:nlsdata.obj
 0002:00001920       ??_C@_1O@PDICJHAG@?$AAF?$AAr?$AAi?$AAd?$AAa?$AAy@ 0000000140015920     libucrt:nlsdata.obj
 0002:00001930       ??_C@_1BC@ENMNNPAJ@?$AAS?$AAa?$AAt?$AAu?$AAr?$AAd?$AAa?$AAy@ 0000000140015930     libucrt:nlsdata.obj
 0002:00001948       ??_C@_17DKNBKCHM@?$AAJ?$AAa?$AAn@ 0000000140015948     libucrt:nlsdata.obj
 0002:00001950       ??_C@_17LMDJEKJN@?$AAF?$AAe?$AAb@ 0000000140015950     libucrt:nlsdata.obj
 0002:00001958       ??_C@_17CKNLEDEC@?$AAM?$AAa?$AAr@ 0000000140015958     libucrt:nlsdata.obj
 0002:00001960       ??_C@_17LFPOIHDD@?$AAA?$AAp?$AAr@ 0000000140015960     libucrt:nlsdata.obj
 0002:00001968       ??_C@_17PNNKMEED@?$AAM?$AAa?$AAy@ 0000000140015968     libucrt:nlsdata.obj
 0002:00001970       ??_C@_17KCJGOCPB@?$AAJ?$AAu?$AAn@ 0000000140015970     libucrt:nlsdata.obj
 0002:00001978       ??_C@_17IJPCKHK@?$AAJ?$AAu?$AAl@ 0000000140015978     libucrt:nlsdata.obj
 0002:00001980       ??_C@_17ICPELBCN@?$AAA?$AAu?$AAg@ 0000000140015980     libucrt:nlsdata.obj
 0002:00001988       ??_C@_17HCHCOKMG@?$AAS?$AAe?$AAp@ 0000000140015988     libucrt:nlsdata.obj
 0002:00001990       ??_C@_17FNLKOI@?$AAO?$AAc?$AAt@ 0000000140015990     libucrt:nlsdata.obj
 0002:00001998       ??_C@_17BBDMLCIG@?$AAN?$AAo?$AAv@ 0000000140015998     libucrt:nlsdata.obj
 0002:000019a0       ??_C@_17EGKACKIF@?$AAD?$AAe?$AAc@ 00000001400159a0     libucrt:nlsdata.obj
 0002:000019a8       ??_C@_1BA@EFMEIEBA@?$AAJ?$AAa?$AAn?$AAu?$AAa?$AAr?$AAy@ 00000001400159a8     libucrt:nlsdata.obj
 0002:000019b8       ??_C@_1BC@JGDDFFAM@?$AAF?$AAe?$AAb?$AAr?$AAu?$AAa?$AAr?$AAy@ 00000001400159b8     libucrt:nlsdata.obj
 0002:000019d0       ??_C@_1M@IKEENEDF@?$AAM?$AAa?$AAr?$AAc?$AAh@ 00000001400159d0     libucrt:nlsdata.obj
 0002:000019e0       ??_C@_1M@GJNLMHFD@?$AAA?$AAp?$AAr?$AAi?$AAl@ 00000001400159e0     libucrt:nlsdata.obj
 0002:000019f0       ??_C@_19EPFLPGAP@?$AAJ?$AAu?$AAn?$AAe@ 00000001400159f0     libucrt:nlsdata.obj
 0002:00001a00       ??_C@_19BIFMLPCD@?$AAJ?$AAu?$AAl?$AAy@ 0000000140015a00     libucrt:nlsdata.obj
 0002:00001a10       ??_C@_1O@PAHLKOAC@?$AAA?$AAu?$AAg?$AAu?$AAs?$AAt@ 0000000140015a10     libucrt:nlsdata.obj
 0002:00001a20       ??_C@_1BE@DKAAMBJL@?$AAS?$AAe?$AAp?$AAt?$AAe?$AAm?$AAb?$AAe?$AAr@ 0000000140015a20     libucrt:nlsdata.obj
 0002:00001a38       ??_C@_1BA@EPANDLNG@?$AAO?$AAc?$AAt?$AAo?$AAb?$AAe?$AAr@ 0000000140015a38     libucrt:nlsdata.obj
 0002:00001a48       ??_C@_1BC@BGLIFPF@?$AAN?$AAo?$AAv?$AAe?$AAm?$AAb?$AAe?$AAr@ 0000000140015a48     libucrt:nlsdata.obj
 0002:00001a60       ??_C@_1BC@FEMKIFH@?$AAD?$AAe?$AAc?$AAe?$AAm?$AAb?$AAe?$AAr@ 0000000140015a60     libucrt:nlsdata.obj
 0002:00001a74       ??_C@_15ODEHAHHF@?$AAA?$AAM@ 0000000140015a74     libucrt:nlsdata.obj
 0002:00001a7c       ??_C@_15CLMNNGEL@?$AAP?$AAM@ 0000000140015a7c     libucrt:nlsdata.obj
 0002:00001a88       ??_C@_1BC@IEBCMHCM@?$AAM?$AAM?$AA?1?$AAd?$AAd?$AA?1?$AAy?$AAy@ 0000000140015a88     libucrt:nlsdata.obj
 0002:00001aa0       ??_C@_1CI@KNAKOEBC@?$AAd?$AAd?$AAd?$AAd?$AA?0?$AA?5?$AAM?$AAM?$AAM?$AAM?$AA?5?$AAd?$AAd?$AA?0?$AA?5@ 0000000140015aa0     libucrt:nlsdata.obj
 0002:00001ac8       ??_C@_1BC@GDGBMEMK@?$AAH?$AAH?$AA?3?$AAm?$AAm?$AA?3?$AAs?$AAs@ 0000000140015ac8     libucrt:nlsdata.obj
 0002:00001ae0       ??_C@_1M@BMHNFIME@?$AAe?$AAn?$AA?9?$AAU?$AAS@ 0000000140015ae0     libucrt:nlsdata.obj
 0002:00001af0       __newctype                 0000000140015af0     libucrt:ctype.obj
 0002:00001df0       __newclmap                 0000000140015df0     libucrt:ctype.obj
 0002:00001f70       __newcumap                 0000000140015f70     libucrt:ctype.obj
 0002:000020f0       _wctype                    00000001400160f0     libucrt:ctype.obj
 0002:00002318       ??_C@_1M@HPNHIDJI@?$AAj?$AAa?$AA?9?$AAJ?$AAP@ 0000000140016318     libucrt:mbctype.obj
 0002:00002328       ??_C@_1M@BIBDDEMK@?$AAz?$AAh?$AA?9?$AAC?$AAN@ 0000000140016328     libucrt:mbctype.obj
 0002:00002338       ??_C@_1M@JLOOOEGK@?$AAk?$AAo?$AA?9?$AAK?$AAR@ 0000000140016338     libucrt:mbctype.obj
 0002:00002348       ??_C@_1M@CLNBBOPM@?$AAz?$AAh?$AA?9?$AAT?$AAW@ 0000000140016348     libucrt:mbctype.obj
 0002:00002354       ??_C@_15PJPFLCCM@?$AAu?$AAk@ 0000000140016354     libucrt:get_qualified_locale.obj
 0002:00002400       ??_C@_1EA@JGEFHKEI@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016400     libucrt:winapi_thunks.obj
 0002:00002440       ??_C@_1DI@IJCEHOCB@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016440     libucrt:winapi_thunks.obj
 0002:00002480       ??_C@_1EI@MPIAOHOC@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016480     libucrt:winapi_thunks.obj
 0002:000024d0       ??_C@_1FK@FPHCKFIE@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 00000001400164d0     libucrt:winapi_thunks.obj
 0002:00002530       ??_C@_1EM@DILCGIIO@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016530     libucrt:winapi_thunks.obj
 0002:00002580       ??_C@_1DM@LNCGDDPN@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016580     libucrt:winapi_thunks.obj
 0002:000025c0       ??_C@_1DO@FPAPJEMD@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 00000001400165c0     libucrt:winapi_thunks.obj
 0002:00002600       ??_C@_1DK@NDHNAHIO@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016600     libucrt:winapi_thunks.obj
 0002:00002640       ??_C@_1DM@KGHDGBCM@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAc?$AAo?$AAr?$AAe@ 0000000140016640     libucrt:winapi_thunks.obj
 0002:00002680       ??_C@_1EO@IJIOEFOH@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAr?$AAt?$AAc?$AAo@ 0000000140016680     libucrt:winapi_thunks.obj
 0002:000026d0       ??_C@_1FG@HHGEKANL@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAs?$AAe?$AAc?$AAu@ 00000001400166d0     libucrt:winapi_thunks.obj
 0002:00002730       ??_C@_1EG@DBIOJECG@?$AAe?$AAx?$AAt?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAn?$AAt?$AAu?$AAs@ 0000000140016730     libucrt:winapi_thunks.obj
 0002:00002780       ??_C@_1EO@FIHMJCLF@?$AAe?$AAx?$AAt?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAn?$AAt?$AAu?$AAs@ 0000000140016780     libucrt:winapi_thunks.obj
 0002:000027d0       ??_C@_1BC@DNHGCMLG@?$AAa?$AAd?$AAv?$AAa?$AAp?$AAi?$AA3?$AA2@ 00000001400167d0     libucrt:winapi_thunks.obj
 0002:000027e8       ??_C@_1M@OAIMIKLP@?$AAn?$AAt?$AAd?$AAl?$AAl@ 00000001400167e8     libucrt:winapi_thunks.obj
 0002:00002800       ??_C@_1EG@DPGNFKGC@?$AAa?$AAp?$AAi?$AA?9?$AAm?$AAs?$AA?9?$AAw?$AAi?$AAn?$AA?9?$AAa?$AAp?$AAp?$AAm@ 0000000140016800     libucrt:winapi_thunks.obj
 0002:00002848       ??_C@_1O@BCCLBEOE@?$AAu?$AAs?$AAe?$AAr?$AA3?$AA2@ 0000000140016848     libucrt:winapi_thunks.obj
 0002:00002888       ??_C@_0O@KKBNKAPF@LCMapStringEx@ 0000000140016888     libucrt:winapi_thunks.obj
 0002:000028a0       ??_C@_0BB@HBDEELFH@LocaleNameToLCID@ 00000001400168a0     libucrt:winapi_thunks.obj
 0002:000028b8       ??_C@_0CF@OJOFEIGO@AppPolicyGetProcessTerminationM@ 00000001400168b8     libucrt:winapi_thunks.obj
 0002:00003720       ??_C@_15EMKDOKLE@?$AAa?$AAr@ 0000000140017720     libucrt:lcidtoname_downlevel.obj
 0002:00003728       ??_C@_15KNPADPLH@?$AAb?$AAg@ 0000000140017728     libucrt:lcidtoname_downlevel.obj
 0002:00003730       ??_C@_15EDMHLDMO@?$AAc?$AAa@ 0000000140017730     libucrt:lcidtoname_downlevel.obj
 0002:00003738       ??_C@_1O@BPEAJADD@?$AAz?$AAh?$AA?9?$AAC?$AAH?$AAS@ 0000000140017738     libucrt:lcidtoname_downlevel.obj
 0002:00003748       ??_C@_15LJNHCMNK@?$AAc?$AAs@ 0000000140017748     libucrt:lcidtoname_downlevel.obj
 0002:00003750       ??_C@_15FOMCIDHG@?$AAd?$AAa@ 0000000140017750     libucrt:lcidtoname_downlevel.obj
 0002:00003758       ??_C@_15NBKABECB@?$AAd?$AAe@ 0000000140017758     libucrt:lcidtoname_downlevel.obj
 0002:00003760       ??_C@_15GHPEIIAO@?$AAe?$AAl@ 0000000140017760     libucrt:lcidtoname_downlevel.obj
 0002:00003768       ??_C@_15MNPNEAIF@?$AAe?$AAn@ 0000000140017768     libucrt:lcidtoname_downlevel.obj
 0002:00003770       ??_C@_15GPIOMPMH@?$AAe?$AAs@ 0000000140017770     libucrt:lcidtoname_downlevel.obj
 0002:00003778       ??_C@_15NGLOAKJC@?$AAf?$AAi@ 0000000140017778     libucrt:lcidtoname_downlevel.obj
 0002:00003780       ??_C@_15FBKGNKAM@?$AAf?$AAr@ 0000000140017780     libucrt:lcidtoname_downlevel.obj
 0002:00003788       ??_C@_15KGGCNEFK@?$AAh?$AAe@ 0000000140017788     libucrt:lcidtoname_downlevel.obj
 0002:00003790       ??_C@_15PGHLIDMF@?$AAh?$AAu@ 0000000140017790     libucrt:lcidtoname_downlevel.obj
 0002:00003798       ??_C@_15BIEMAPLM@?$AAi?$AAs@ 0000000140017798     libucrt:lcidtoname_downlevel.obj
 0002:000037a0       ??_C@_15IFJLDHAF@?$AAi?$AAt@ 00000001400177a0     libucrt:lcidtoname_downlevel.obj
 0002:000037a8       ??_C@_15GEMIOCAG@?$AAj?$AAa@ 00000001400177a8     libucrt:lcidtoname_downlevel.obj
 0002:000037b0       ??_C@_15EPELEGJA@?$AAk?$AAo@ 00000001400177b0     libucrt:lcidtoname_downlevel.obj
 0002:000037b8       ??_C@_15NDDHIMN@?$AAn?$AAl@ 00000001400177b8     libucrt:lcidtoname_downlevel.obj
 0002:000037c0       ??_C@_15BPIGNHCD@?$AAn?$AAo@ 00000001400177c0     libucrt:lcidtoname_downlevel.obj
 0002:000037c8       ??_C@_15DEOPBLCG@?$AAp?$AAl@ 00000001400177c8     libucrt:lcidtoname_downlevel.obj
 0002:000037d0       ??_C@_15KBECGEFG@?$AAp?$AAt@ 00000001400177d0     libucrt:lcidtoname_downlevel.obj
 0002:000037d8       ??_C@_15GLJCBFMD@?$AAr?$AAo@ 00000001400177d8     libucrt:lcidtoname_downlevel.obj
 0002:000037e0       ??_C@_15FEDGKCDI@?$AAr?$AAu@ 00000001400177e0     libucrt:lcidtoname_downlevel.obj
 0002:000037e8       ??_C@_15GLKMLLHM@?$AAh?$AAr@ 00000001400177e8     libucrt:lcidtoname_downlevel.obj
 0002:000037f0       ??_C@_15CPKMFBDB@?$AAs?$AAk@ 00000001400177f0     libucrt:lcidtoname_downlevel.obj
 0002:000037f8       ??_C@_15BAAIOGMK@?$AAs?$AAq@ 00000001400177f8     libucrt:lcidtoname_downlevel.obj
 0002:00003800       ??_C@_15INNPNOHD@?$AAs?$AAv@ 0000000140017800     libucrt:lcidtoname_downlevel.obj
 0002:00003808       ??_C@_15CABMMOGH@?$AAt?$AAh@ 0000000140017808     libucrt:lcidtoname_downlevel.obj
 0002:00003810       ??_C@_15BPLIHJJM@?$AAt?$AAr@ 0000000140017810     libucrt:lcidtoname_downlevel.obj
 0002:00003818       ??_C@_15NEOEKKDJ@?$AAu?$AAr@ 0000000140017818     libucrt:lcidtoname_downlevel.obj
 0002:00003820       ??_C@_15NFICGAJK@?$AAi?$AAd@ 0000000140017820     libucrt:lcidtoname_downlevel.obj
 0002:00003828       ??_C@_15HPJPHDM@?$AAb?$AAe@ 0000000140017828     libucrt:lcidtoname_downlevel.obj
 0002:00003830       ??_C@_15LCHLGJII@?$AAs?$AAl@ 0000000140017830     libucrt:lcidtoname_downlevel.obj
 0002:00003838       ??_C@_15PCFJPHHO@?$AAe?$AAt@ 0000000140017838     libucrt:lcidtoname_downlevel.obj
 0002:00003840       ??_C@_15HPFPGODN@?$AAl?$AAv@ 0000000140017840     libucrt:lcidtoname_downlevel.obj
 0002:00003848       ??_C@_15NFFGKGLG@?$AAl?$AAt@ 0000000140017848     libucrt:lcidtoname_downlevel.obj
 0002:00003850       ??_C@_15BDAKCCHN@?$AAf?$AAa@ 0000000140017850     libucrt:lcidtoname_downlevel.obj
 0002:00003858       ??_C@_15NFGIAIAJ@?$AAv?$AAi@ 0000000140017858     libucrt:lcidtoname_downlevel.obj
 0002:00003860       ??_C@_15LMKNDMHN@?$AAh?$AAy@ 0000000140017860     libucrt:lcidtoname_downlevel.obj
 0002:00003868       ??_C@_15IJBHMCFL@?$AAa?$AAz@ 0000000140017868     libucrt:lcidtoname_downlevel.obj
 0002:00003870       ??_C@_15EKOFJABL@?$AAe?$AAu@ 0000000140017870     libucrt:lcidtoname_downlevel.obj
 0002:00003878       ??_C@_15BGHADCNK@?$AAm?$AAk@ 0000000140017878     libucrt:lcidtoname_downlevel.obj
 0002:00003880       ??_C@_15JDNICKHM@?$AAa?$AAf@ 0000000140017880     libucrt:lcidtoname_downlevel.obj
 0002:00003888       ??_C@_15KPJEDBKD@?$AAk?$AAa@ 0000000140017888     libucrt:lcidtoname_downlevel.obj
 0002:00003890       ??_C@_15PDNFFFEO@?$AAf?$AAo@ 0000000140017890     libucrt:lcidtoname_downlevel.obj
 0002:00003898       ??_C@_15OMLEGLOC@?$AAh?$AAi@ 0000000140017898     libucrt:lcidtoname_downlevel.obj
 0002:000038a0       ??_C@_15IDNNENKK@?$AAm?$AAs@ 00000001400178a0     libucrt:lcidtoname_downlevel.obj
 0002:000038a8       ??_C@_15MACJNBMH@?$AAk?$AAk@ 00000001400178a8     libucrt:lcidtoname_downlevel.obj
 0002:000038b0       ??_C@_15DKDJEOND@?$AAk?$AAy@ 00000001400178b0     libucrt:lcidtoname_downlevel.obj
 0002:000038b8       ??_C@_15DFGDLJBG@?$AAs?$AAw@ 00000001400178b8     libucrt:lcidtoname_downlevel.obj
 0002:000038c0       ??_C@_15BBFAICNG@?$AAu?$AAz@ 00000001400178c0     libucrt:lcidtoname_downlevel.obj
 0002:000038c8       ??_C@_15DKNDCGEA@?$AAt?$AAt@ 00000001400178c8     libucrt:lcidtoname_downlevel.obj
 0002:000038d0       ??_C@_15MGIFMDPL@?$AAp?$AAa@ 00000001400178d0     libucrt:lcidtoname_downlevel.obj
 0002:000038d8       ??_C@_15HCNDBBA@?$AAg?$AAu@ 00000001400178d8     libucrt:lcidtoname_downlevel.obj
 0002:000038e0       ??_C@_15FNBEIBON@?$AAt?$AAa@ 00000001400178e0     libucrt:lcidtoname_downlevel.obj
 0002:000038e8       ??_C@_15NCHGBGLK@?$AAt?$AAe@ 00000001400178e8     libucrt:lcidtoname_downlevel.obj
 0002:000038f0       ??_C@_15PHPHCBPF@?$AAk?$AAn@ 00000001400178f0     libucrt:lcidtoname_downlevel.obj
 0002:000038f8       ??_C@_15DLGBCKMP@?$AAm?$AAr@ 00000001400178f8     libucrt:lcidtoname_downlevel.obj
 0002:00003900       ??_C@_15EABBLBFF@?$AAs?$AAa@ 0000000140017900     libucrt:lcidtoname_downlevel.obj
 0002:00003908       ??_C@_15CBKOMCOI@?$AAm?$AAn@ 0000000140017908     libucrt:lcidtoname_downlevel.obj
 0002:00003910       ??_C@_15CKDMCJAF@?$AAg?$AAl@ 0000000140017910     libucrt:lcidtoname_downlevel.obj
 0002:00003918       ??_C@_17CNJFBPG@?$AAk?$AAo?$AAk@ 0000000140017918     libucrt:lcidtoname_downlevel.obj
 0002:00003920       ??_C@_17FFBJICPL@?$AAs?$AAy?$AAr@ 0000000140017920     libucrt:lcidtoname_downlevel.obj
 0002:00003928       ??_C@_17KPNDCPAF@?$AAd?$AAi?$AAv@ 0000000140017928     libucrt:lcidtoname_downlevel.obj
 0002:00003930       ??_C@_11LOCGONAA@@         0000000140017930     libucrt:lcidtoname_downlevel.obj
 0002:00003938       ??_C@_1M@OKAHONE@?$AAa?$AAr?$AA?9?$AAS?$AAA@ 0000000140017938     libucrt:lcidtoname_downlevel.obj
 0002:00003948       ??_C@_1M@FFFIGIGK@?$AAb?$AAg?$AA?9?$AAB?$AAG@ 0000000140017948     libucrt:lcidtoname_downlevel.obj
 0002:00003958       ??_C@_1M@BJNKEDC@?$AAc?$AAa?$AA?9?$AAE?$AAS@ 0000000140017958     libucrt:lcidtoname_downlevel.obj
 0002:00003968       ??_C@_1M@IJJHFJHA@?$AAc?$AAs?$AA?9?$AAC?$AAZ@ 0000000140017968     libucrt:lcidtoname_downlevel.obj
 0002:00003978       ??_C@_1M@CLPEOBGI@?$AAd?$AAa?$AA?9?$AAD?$AAK@ 0000000140017978     libucrt:lcidtoname_downlevel.obj
 0002:00003988       ??_C@_1M@MCMADGCB@?$AAd?$AAe?$AA?9?$AAD?$AAE@ 0000000140017988     libucrt:lcidtoname_downlevel.obj
 0002:00003998       ??_C@_1M@OOCKEMAM@?$AAe?$AAl?$AA?9?$AAG?$AAR@ 0000000140017998     libucrt:lcidtoname_downlevel.obj
 0002:000039a8       ??_C@_1M@DDNJFGID@?$AAf?$AAi?$AA?9?$AAF?$AAI@ 00000001400179a8     libucrt:lcidtoname_downlevel.obj
 0002:000039b8       ??_C@_1M@GLIPPMAC@?$AAf?$AAr?$AA?9?$AAF?$AAR@ 00000001400179b8     libucrt:lcidtoname_downlevel.obj
 0002:000039c8       ??_C@_1M@GFMCHPE@?$AAh?$AAe?$AA?9?$AAI?$AAL@ 00000001400179c8     libucrt:lcidtoname_downlevel.obj
 0002:000039d8       ??_C@_1M@MHLPGNKM@?$AAh?$AAu?$AA?9?$AAH?$AAU@ 00000001400179d8     libucrt:lcidtoname_downlevel.obj
 0002:000039e8       ??_C@_1M@LPDDNNPN@?$AAi?$AAs?$AA?9?$AAI?$AAS@ 00000001400179e8     libucrt:lcidtoname_downlevel.obj
 0002:000039f8       ??_C@_1M@MADIPODN@?$AAi?$AAt?$AA?9?$AAI?$AAT@ 00000001400179f8     libucrt:lcidtoname_downlevel.obj
 0002:00003a08       ??_C@_1M@IHBJJGG@?$AAn?$AAl?$AA?9?$AAN?$AAL@ 0000000140017a08     libucrt:lcidtoname_downlevel.obj
 0002:00003a18       ??_C@_1M@EANAGDL@?$AAn?$AAb?$AA?9?$AAN?$AAO@ 0000000140017a18     libucrt:lcidtoname_downlevel.obj
 0002:00003a28       ??_C@_1M@NEIEMEGP@?$AAp?$AAl?$AA?9?$AAP?$AAL@ 0000000140017a28     libucrt:lcidtoname_downlevel.obj
 0002:00003a38       ??_C@_1M@BOCFIGEP@?$AAp?$AAt?$AA?9?$AAB?$AAR@ 0000000140017a38     libucrt:lcidtoname_downlevel.obj
 0002:00003a48       ??_C@_1M@IMPFOPBG@?$AAr?$AAo?$AA?9?$AAR?$AAO@ 0000000140017a48     libucrt:lcidtoname_downlevel.obj
 0002:00003a58       ??_C@_1M@IDNNEJMM@?$AAr?$AAu?$AA?9?$AAR?$AAU@ 0000000140017a58     libucrt:lcidtoname_downlevel.obj
 0002:00003a68       ??_C@_1M@LILEEOGM@?$AAh?$AAr?$AA?9?$AAH?$AAR@ 0000000140017a68     libucrt:lcidtoname_downlevel.obj
 0002:00003a78       ??_C@_1M@FKIFEHPB@?$AAs?$AAk?$AA?9?$AAS?$AAK@ 0000000140017a78     libucrt:lcidtoname_downlevel.obj
 0002:00003a88       ??_C@_1M@LJMAMNPJ@?$AAs?$AAq?$AA?9?$AAA?$AAL@ 0000000140017a88     libucrt:lcidtoname_downlevel.obj
 0002:00003a98       ??_C@_1M@GIAKDKJK@?$AAs?$AAv?$AA?9?$AAS?$AAE@ 0000000140017a98     libucrt:lcidtoname_downlevel.obj
 0002:00003aa8       ??_C@_1M@MKJKIKCL@?$AAt?$AAh?$AA?9?$AAT?$AAH@ 0000000140017aa8     libucrt:lcidtoname_downlevel.obj
 0002:00003ab8       ??_C@_1M@MFLCCMPB@?$AAt?$AAr?$AA?9?$AAT?$AAR@ 0000000140017ab8     libucrt:lcidtoname_downlevel.obj
 0002:00003ac8       ??_C@_1M@OIJHDKJN@?$AAu?$AAr?$AA?9?$AAP?$AAK@ 0000000140017ac8     libucrt:lcidtoname_downlevel.obj
 0002:00003ad8       ??_C@_1M@LHIPCIEK@?$AAi?$AAd?$AA?9?$AAI?$AAD@ 0000000140017ad8     libucrt:lcidtoname_downlevel.obj
 0002:00003ae8       ??_C@_1M@MFMOBGI@?$AAu?$AAk?$AA?9?$AAU?$AAA@ 0000000140017ae8     libucrt:lcidtoname_downlevel.obj
 0002:00003af8       ??_C@_1M@OBGLJIPL@?$AAb?$AAe?$AA?9?$AAB?$AAY@ 0000000140017af8     libucrt:lcidtoname_downlevel.obj
 0002:00003b08       ??_C@_1M@BCFAJEAD@?$AAs?$AAl?$AA?9?$AAS?$AAI@ 0000000140017b08     libucrt:lcidtoname_downlevel.obj
 0002:00003b18       ??_C@_1M@FKFFEDDN@?$AAe?$AAt?$AA?9?$AAE?$AAE@ 0000000140017b18     libucrt:lcidtoname_downlevel.obj
 0002:00003b28       ??_C@_1M@KGKKAACI@?$AAl?$AAv?$AA?9?$AAL?$AAV@ 0000000140017b28     libucrt:lcidtoname_downlevel.obj
 0002:00003b38       ??_C@_1M@IFGBIJO@?$AAl?$AAt?$AA?9?$AAL?$AAT@ 0000000140017b38     libucrt:lcidtoname_downlevel.obj
 0002:00003b48       ??_C@_1M@FGEAHEDM@?$AAf?$AAa?$AA?9?$AAI?$AAR@ 0000000140017b48     libucrt:lcidtoname_downlevel.obj
 0002:00003b58       ??_C@_1M@KBMAIBFN@?$AAv?$AAi?$AA?9?$AAV?$AAN@ 0000000140017b58     libucrt:lcidtoname_downlevel.obj
 0002:00003b68       ??_C@_1M@GPCBKDJK@?$AAh?$AAy?$AA?9?$AAA?$AAM@ 0000000140017b68     libucrt:lcidtoname_downlevel.obj
 0002:00003b78       ??_C@_1BG@BECMDDJB@?$AAa?$AAz?$AA?9?$AAA?$AAZ?$AA?9?$AAL?$AAa?$AAt?$AAn@ 0000000140017b78     libucrt:lcidtoname_downlevel.obj
 0002:00003b90       ??_C@_1M@MAOFCAEA@?$AAe?$AAu?$AA?9?$AAE?$AAS@ 0000000140017b90     libucrt:lcidtoname_downlevel.obj
 0002:00003ba0       ??_C@_1M@IGHABKPI@?$AAm?$AAk?$AA?9?$AAM?$AAK@ 0000000140017ba0     libucrt:lcidtoname_downlevel.obj
 0002:00003bb0       ??_C@_1M@IAIGNEJG@?$AAt?$AAn?$AA?9?$AAZ?$AAA@ 0000000140017bb0     libucrt:lcidtoname_downlevel.obj
 0002:00003bc0       ??_C@_1M@IIJCOJFA@?$AAx?$AAh?$AA?9?$AAZ?$AAA@ 0000000140017bc0     libucrt:lcidtoname_downlevel.obj
 0002:00003bd0       ??_C@_1M@LGPJHNJH@?$AAz?$AAu?$AA?9?$AAZ?$AAA@ 0000000140017bd0     libucrt:lcidtoname_downlevel.obj
 0002:00003be0       ??_C@_1M@HOKAOIO@?$AAa?$AAf?$AA?9?$AAZ?$AAA@ 0000000140017be0     libucrt:lcidtoname_downlevel.obj
 0002:00003bf0       ??_C@_1M@DPCLHLIE@?$AAk?$AAa?$AA?9?$AAG?$AAE@ 0000000140017bf0     libucrt:lcidtoname_downlevel.obj
 0002:00003c00       ??_C@_1M@BLKMHJBI@?$AAf?$AAo?$AA?9?$AAF?$AAO@ 0000000140017c00     libucrt:lcidtoname_downlevel.obj
 0002:00003c10       ??_C@_1M@LGGJAPPB@?$AAh?$AAi?$AA?9?$AAI?$AAN@ 0000000140017c10     libucrt:lcidtoname_downlevel.obj
 0002:00003c20       ??_C@_1M@FIKPIHFE@?$AAm?$AAt?$AA?9?$AAM?$AAT@ 0000000140017c20     libucrt:lcidtoname_downlevel.obj
 0002:00003c30       ??_C@_1M@HEGGPBFA@?$AAs?$AAe?$AA?9?$AAN?$AAO@ 0000000140017c30     libucrt:lcidtoname_downlevel.obj
 0002:00003c40       ??_C@_1M@EIBJEEPA@?$AAm?$AAs?$AA?9?$AAM?$AAY@ 0000000140017c40     libucrt:lcidtoname_downlevel.obj
 0002:00003c50       ??_C@_1M@FHLBGMPP@?$AAk?$AAk?$AA?9?$AAK?$AAZ@ 0000000140017c50     libucrt:lcidtoname_downlevel.obj
 0002:00003c60       ??_C@_1M@NGJJLCGI@?$AAk?$AAy?$AA?9?$AAK?$AAG@ 0000000140017c60     libucrt:lcidtoname_downlevel.obj
 0002:00003c70       ??_C@_1M@GIENNBFC@?$AAs?$AAw?$AA?9?$AAK?$AAE@ 0000000140017c70     libucrt:lcidtoname_downlevel.obj
 0002:00003c80       ??_C@_1BG@NDGMJIMJ@?$AAu?$AAz?$AA?9?$AAU?$AAZ?$AA?9?$AAL?$AAa?$AAt?$AAn@ 0000000140017c80     libucrt:lcidtoname_downlevel.obj
 0002:00003c98       ??_C@_1M@IDCCIHBC@?$AAt?$AAt?$AA?9?$AAR?$AAU@ 0000000140017c98     libucrt:lcidtoname_downlevel.obj
 0002:00003ca8       ??_C@_1M@LOICPMOJ@?$AAb?$AAn?$AA?9?$AAI?$AAN@ 0000000140017ca8     libucrt:lcidtoname_downlevel.obj
 0002:00003cb8       ??_C@_1M@KPKKNEAH@?$AAp?$AAa?$AA?9?$AAI?$AAN@ 0000000140017cb8     libucrt:lcidtoname_downlevel.obj
 0002:00003cc8       ??_C@_1M@PJGPPBOG@?$AAg?$AAu?$AA?9?$AAI?$AAN@ 0000000140017cc8     libucrt:lcidtoname_downlevel.obj
 0002:00003cd8       ??_C@_1M@KMKMOPHI@?$AAt?$AAa?$AA?9?$AAI?$AAN@ 0000000140017cd8     libucrt:lcidtoname_downlevel.obj
 0002:00003ce8       ??_C@_1M@KFEHEPAC@?$AAt?$AAe?$AA?9?$AAI?$AAN@ 0000000140017ce8     libucrt:lcidtoname_downlevel.obj
 0002:00003cf8       ??_C@_1M@CDCLMGHI@?$AAk?$AAn?$AA?9?$AAI?$AAN@ 0000000140017cf8     libucrt:lcidtoname_downlevel.obj
 0002:00003d08       ??_C@_1M@MIODLDKF@?$AAm?$AAl?$AA?9?$AAI?$AAN@ 0000000140017d08     libucrt:lcidtoname_downlevel.obj
 0002:00003d18       ??_C@_1M@PBIEACPO@?$AAm?$AAr?$AA?9?$AAI?$AAN@ 0000000140017d18     libucrt:lcidtoname_downlevel.obj
 0002:00003d28       ??_C@_1M@NIDEAGPH@?$AAs?$AAa?$AA?9?$AAI?$AAN@ 0000000140017d28     libucrt:lcidtoname_downlevel.obj
 0002:00003d38       ??_C@_1M@FHIHCBIO@?$AAm?$AAn?$AA?9?$AAM?$AAN@ 0000000140017d38     libucrt:lcidtoname_downlevel.obj
 0002:00003d48       ??_C@_1M@JAIJPENP@?$AAc?$AAy?$AA?9?$AAG?$AAB@ 0000000140017d48     libucrt:lcidtoname_downlevel.obj
 0002:00003d58       ??_C@_1M@PHGFBEPN@?$AAg?$AAl?$AA?9?$AAE?$AAS@ 0000000140017d58     libucrt:lcidtoname_downlevel.obj
 0002:00003d68       ??_C@_1O@KPIPDNCP@?$AAk?$AAo?$AAk?$AA?9?$AAI?$AAN@ 0000000140017d68     libucrt:lcidtoname_downlevel.obj
 0002:00003d78       ??_C@_1O@KNHJLDJA@?$AAs?$AAy?$AAr?$AA?9?$AAS?$AAY@ 0000000140017d78     libucrt:lcidtoname_downlevel.obj
 0002:00003d88       ??_C@_1O@MKEKBLAH@?$AAd?$AAi?$AAv?$AA?9?$AAM?$AAV@ 0000000140017d88     libucrt:lcidtoname_downlevel.obj
 0002:00003d98       ??_C@_1O@OHDCKDDF@?$AAq?$AAu?$AAz?$AA?9?$AAB?$AAO@ 0000000140017d98     libucrt:lcidtoname_downlevel.obj
 0002:00003da8       ??_C@_1M@LEPJNLFD@?$AAn?$AAs?$AA?9?$AAZ?$AAA@ 0000000140017da8     libucrt:lcidtoname_downlevel.obj
 0002:00003db8       ??_C@_1M@OMLEIIJB@?$AAm?$AAi?$AA?9?$AAN?$AAZ@ 0000000140017db8     libucrt:lcidtoname_downlevel.obj
 0002:00003dc8       ??_C@_1M@PMPEAILG@?$AAa?$AAr?$AA?9?$AAI?$AAQ@ 0000000140017dc8     libucrt:lcidtoname_downlevel.obj
 0002:00003dd8       ??_C@_1M@CNKPNOEE@?$AAd?$AAe?$AA?9?$AAC?$AAH@ 0000000140017dd8     libucrt:lcidtoname_downlevel.obj
 0002:00003de8       ??_C@_1M@LKMGMLKO@?$AAe?$AAn?$AA?9?$AAG?$AAB@ 0000000140017de8     libucrt:lcidtoname_downlevel.obj
 0002:00003df8       ??_C@_1M@PGKJFFGL@?$AAe?$AAs?$AA?9?$AAM?$AAX@ 0000000140017df8     libucrt:lcidtoname_downlevel.obj
 0002:00003e08       ??_C@_1M@DNNANBDC@?$AAf?$AAr?$AA?9?$AAB?$AAE@ 0000000140017e08     libucrt:lcidtoname_downlevel.obj
 0002:00003e18       ??_C@_1M@HLGMDFHM@?$AAi?$AAt?$AA?9?$AAC?$AAH@ 0000000140017e18     libucrt:lcidtoname_downlevel.obj
 0002:00003e28       ??_C@_1M@CLLBGJH@?$AAn?$AAl?$AA?9?$AAB?$AAE@ 0000000140017e28     libucrt:lcidtoname_downlevel.obj
 0002:00003e38       ??_C@_1M@BODBOGLF@?$AAn?$AAn?$AA?9?$AAN?$AAO@ 0000000140017e38     libucrt:lcidtoname_downlevel.obj
 0002:00003e48       ??_C@_1M@HFFAHKAD@?$AAp?$AAt?$AA?9?$AAP?$AAT@ 0000000140017e48     libucrt:lcidtoname_downlevel.obj
 0002:00003e58       ??_C@_1BG@LNOAKHIE@?$AAs?$AAr?$AA?9?$AAS?$AAP?$AA?9?$AAL?$AAa?$AAt?$AAn@ 0000000140017e58     libucrt:lcidtoname_downlevel.obj
 0002:00003e70       ??_C@_1M@HBMHBGAK@?$AAs?$AAv?$AA?9?$AAF?$AAI@ 0000000140017e70     libucrt:lcidtoname_downlevel.obj
 0002:00003e80       ??_C@_1BG@DGCJGJBE@?$AAa?$AAz?$AA?9?$AAA?$AAZ?$AA?9?$AAC?$AAy?$AAr?$AAl@ 0000000140017e80     libucrt:lcidtoname_downlevel.obj
 0002:00003e98       ??_C@_1M@KEJDAAHB@?$AAs?$AAe?$AA?9?$AAS?$AAE@ 0000000140017e98     libucrt:lcidtoname_downlevel.obj
 0002:00003ea8       ??_C@_1M@HEIBJJAD@?$AAm?$AAs?$AA?9?$AAB?$AAN@ 0000000140017ea8     libucrt:lcidtoname_downlevel.obj
 0002:00003eb8       ??_C@_1BG@PBGJMCEM@?$AAu?$AAz?$AA?9?$AAU?$AAZ?$AA?9?$AAC?$AAy?$AAr?$AAl@ 0000000140017eb8     libucrt:lcidtoname_downlevel.obj
 0002:00003ed0       ??_C@_1O@LAOBCMDF@?$AAq?$AAu?$AAz?$AA?9?$AAE?$AAC@ 0000000140017ed0     libucrt:lcidtoname_downlevel.obj
 0002:00003ee0       ??_C@_1M@POEEMAIO@?$AAa?$AAr?$AA?9?$AAE?$AAG@ 0000000140017ee0     libucrt:lcidtoname_downlevel.obj
 0002:00003ef0       ??_C@_1M@EFAKDEDL@?$AAz?$AAh?$AA?9?$AAH?$AAK@ 0000000140017ef0     libucrt:lcidtoname_downlevel.obj
 0002:00003f00       ??_C@_1M@HKKIJHGI@?$AAd?$AAe?$AA?9?$AAA?$AAT@ 0000000140017f00     libucrt:lcidtoname_downlevel.obj
 0002:00003f10       ??_C@_1M@KBFBEHJF@?$AAe?$AAn?$AA?9?$AAA?$AAU@ 0000000140017f10     libucrt:lcidtoname_downlevel.obj
 0002:00003f20       ??_C@_1M@MNPLFAAH@?$AAe?$AAs?$AA?9?$AAE?$AAS@ 0000000140017f20     libucrt:lcidtoname_downlevel.obj
 0002:00003f30       ??_C@_1M@HJOOJFMA@?$AAf?$AAr?$AA?9?$AAC?$AAA@ 0000000140017f30     libucrt:lcidtoname_downlevel.obj
 0002:00003f40       ??_C@_1BG@JPOFPNAB@?$AAs?$AAr?$AA?9?$AAS?$AAP?$AA?9?$AAC?$AAy?$AAr?$AAl@ 0000000140017f40     libucrt:lcidtoname_downlevel.obj
 0002:00003f58       ??_C@_1M@LNFOCMOB@?$AAs?$AAe?$AA?9?$AAF?$AAI@ 0000000140017f58     libucrt:lcidtoname_downlevel.obj
 0002:00003f68       ??_C@_1O@MGJBOAMB@?$AAq?$AAu?$AAz?$AA?9?$AAP?$AAE@ 0000000140017f68     libucrt:lcidtoname_downlevel.obj
 0002:00003f78       ??_C@_1M@GJINLBOK@?$AAa?$AAr?$AA?9?$AAL?$AAY@ 0000000140017f78     libucrt:lcidtoname_downlevel.obj
 0002:00003f88       ??_C@_1M@GGMNHJNL@?$AAz?$AAh?$AA?9?$AAS?$AAG@ 0000000140017f88     libucrt:lcidtoname_downlevel.obj
 0002:00003f98       ??_C@_1M@HOIKODND@?$AAd?$AAe?$AA?9?$AAL?$AAU@ 0000000140017f98     libucrt:lcidtoname_downlevel.obj
 0002:00003fa8       ??_C@_1M@DDOCCGFG@?$AAe?$AAn?$AA?9?$AAC?$AAA@ 0000000140017fa8     libucrt:lcidtoname_downlevel.obj
 0002:00003fb8       ??_C@_1M@BNOEMJLF@?$AAe?$AAs?$AA?9?$AAG?$AAT@ 0000000140017fb8     libucrt:lcidtoname_downlevel.obj
 0002:00003fc8       ??_C@_1M@EOGNKEK@?$AAf?$AAr?$AA?9?$AAC?$AAH@ 0000000140017fc8     libucrt:lcidtoname_downlevel.obj
 0002:00003fd8       ??_C@_1M@FLIDJFHL@?$AAh?$AAr?$AA?9?$AAB?$AAA@ 0000000140017fd8     libucrt:lcidtoname_downlevel.obj
 0002:00003fe8       ??_C@_1O@FMCELNAJ@?$AAs?$AAm?$AAj?$AA?9?$AAN?$AAO@ 0000000140017fe8     libucrt:lcidtoname_downlevel.obj
 0002:00003ff8       ??_C@_1M@JHGLJMGJ@?$AAa?$AAr?$AA?9?$AAD?$AAZ@ 0000000140017ff8     libucrt:lcidtoname_downlevel.obj
 0002:00004008       ??_C@_1M@JKKFDCNP@?$AAz?$AAh?$AA?9?$AAM?$AAO@ 0000000140018008     libucrt:lcidtoname_downlevel.obj
 0002:00004018       ??_C@_1M@GEEFALPE@?$AAd?$AAe?$AA?9?$AAL?$AAI@ 0000000140018018     libucrt:lcidtoname_downlevel.obj
 0002:00004028       ??_C@_1M@IGEOFBG@?$AAe?$AAn?$AA?9?$AAN?$AAZ@ 0000000140018028     libucrt:lcidtoname_downlevel.obj
 0002:00004038       ??_C@_1M@KDBONEHP@?$AAe?$AAs?$AA?9?$AAC?$AAR@ 0000000140018038     libucrt:lcidtoname_downlevel.obj
 0002:00004048       ??_C@_1M@FHMDOHNN@?$AAf?$AAr?$AA?9?$AAL?$AAU@ 0000000140018048     libucrt:lcidtoname_downlevel.obj
 0002:00004058       ??_C@_1BG@NFKKMAFG@?$AAb?$AAs?$AA?9?$AAB?$AAA?$AA?9?$AAL?$AAa?$AAt?$AAn@ 0000000140018058     libucrt:lcidtoname_downlevel.obj
 0002:00004070       ??_C@_1O@IMNBEMCI@?$AAs?$AAm?$AAj?$AA?9?$AAS?$AAE@ 0000000140018070     libucrt:lcidtoname_downlevel.obj
 0002:00004080       ??_C@_1M@DHHMBNDP@?$AAa?$AAr?$AA?9?$AAM?$AAA@ 0000000140018080     libucrt:lcidtoname_downlevel.obj
 0002:00004090       ??_C@_1M@BNBLJCGH@?$AAe?$AAn?$AA?9?$AAI?$AAE@ 0000000140018090     libucrt:lcidtoname_downlevel.obj
 0002:000040a0       ??_C@_1M@GEPAFMDL@?$AAe?$AAs?$AA?9?$AAP?$AAA@ 00000001400180a0     libucrt:lcidtoname_downlevel.obj
 0002:000040b0       ??_C@_1M@OJONDMDL@?$AAf?$AAr?$AA?9?$AAM?$AAC@ 00000001400180b0     libucrt:lcidtoname_downlevel.obj
 0002:000040c0       ??_C@_1BG@OBCNFJB@?$AAs?$AAr?$AA?9?$AAB?$AAA?$AA?9?$AAL?$AAa?$AAt?$AAn@ 00000001400180c0     libucrt:lcidtoname_downlevel.obj
 0002:000040d8       ??_C@_1O@KEMEEGPO@?$AAs?$AAm?$AAa?$AA?9?$AAN?$AAO@ 00000001400180d8     libucrt:lcidtoname_downlevel.obj
 0002:000040e8       ??_C@_1M@ELMGFODK@?$AAa?$AAr?$AA?9?$AAT?$AAN@ 00000001400180e8     libucrt:lcidtoname_downlevel.obj
 0002:000040f8       ??_C@_1M@BHDLHFAF@?$AAe?$AAn?$AA?9?$AAZ?$AAA@ 00000001400180f8     libucrt:lcidtoname_downlevel.obj
 0002:00004108       ??_C@_1M@BMGIGLIF@?$AAe?$AAs?$AA?9?$AAD?$AAO@ 0000000140018108     libucrt:lcidtoname_downlevel.obj
 0002:00004118       ??_C@_1BG@CMBHIPBE@?$AAs?$AAr?$AA?9?$AAB?$AAA?$AA?9?$AAC?$AAy?$AAr?$AAl@ 0000000140018118     libucrt:lcidtoname_downlevel.obj
 0002:00004130       ??_C@_1O@HEDBLHNP@?$AAs?$AAm?$AAa?$AA?9?$AAS?$AAE@ 0000000140018130     libucrt:lcidtoname_downlevel.obj
 0002:00004140       ??_C@_1M@DAGCADIM@?$AAa?$AAr?$AA?9?$AAO?$AAM@ 0000000140018140     libucrt:lcidtoname_downlevel.obj
 0002:00004150       ??_C@_1M@FODLMICG@?$AAe?$AAn?$AA?9?$AAJ?$AAM@ 0000000140018150     libucrt:lcidtoname_downlevel.obj
 0002:00004160       ??_C@_1M@DNMLCIHB@?$AAe?$AAs?$AA?9?$AAV?$AAE@ 0000000140018160     libucrt:lcidtoname_downlevel.obj
 0002:00004170       ??_C@_1O@EOKHMKJK@?$AAs?$AAm?$AAs?$AA?9?$AAF?$AAI@ 0000000140018170     libucrt:lcidtoname_downlevel.obj
 0002:00004180       ??_C@_1M@CAFJMKOF@?$AAa?$AAr?$AA?9?$AAY?$AAE@ 0000000140018180     libucrt:lcidtoname_downlevel.obj
 0002:00004190       ??_C@_1M@CBFHIJLI@?$AAe?$AAn?$AA?9?$AAC?$AAB@ 0000000140018190     libucrt:lcidtoname_downlevel.obj
 0002:000041a0       ??_C@_1M@BGNFLDN@?$AAe?$AAs?$AA?9?$AAC?$AAO@ 00000001400181a0     libucrt:lcidtoname_downlevel.obj
 0002:000041b0       ??_C@_1O@JMPHMAMC@?$AAs?$AAm?$AAn?$AA?9?$AAF?$AAI@ 00000001400181b0     libucrt:lcidtoname_downlevel.obj
 0002:000041c0       ??_C@_1M@JLANABKE@?$AAa?$AAr?$AA?9?$AAS?$AAY@ 00000001400181c0     libucrt:lcidtoname_downlevel.obj
 0002:000041d0       ??_C@_1M@HPKGCFGN@?$AAe?$AAn?$AA?9?$AAB?$AAZ@ 00000001400181d0     libucrt:lcidtoname_downlevel.obj
 0002:000041e0       ??_C@_1M@OLJCMLGM@?$AAe?$AAs?$AA?9?$AAP?$AAE@ 00000001400181e0     libucrt:lcidtoname_downlevel.obj
 0002:000041f0       ??_C@_1M@MKKGFKLE@?$AAa?$AAr?$AA?9?$AAJ?$AAO@ 00000001400181f0     libucrt:lcidtoname_downlevel.obj
 0002:00004200       ??_C@_1M@EKPGLDNI@?$AAe?$AAn?$AA?9?$AAT?$AAT@ 0000000140018200     libucrt:lcidtoname_downlevel.obj
 0002:00004210       ??_C@_1M@OONGHFHE@?$AAe?$AAs?$AA?9?$AAA?$AAR@ 0000000140018210     libucrt:lcidtoname_downlevel.obj
 0002:00004220       ??_C@_1M@OOJFGBHE@?$AAa?$AAr?$AA?9?$AAL?$AAB@ 0000000140018220     libucrt:lcidtoname_downlevel.obj
 0002:00004230       ??_C@_1M@GCEJHNEG@?$AAe?$AAn?$AA?9?$AAZ?$AAW@ 0000000140018230     libucrt:lcidtoname_downlevel.obj
 0002:00004240       ??_C@_1M@JNOCAHJI@?$AAe?$AAs?$AA?9?$AAE?$AAC@ 0000000140018240     libucrt:lcidtoname_downlevel.obj
 0002:00004250       ??_C@_1M@JEFHPGGB@?$AAa?$AAr?$AA?9?$AAK?$AAW@ 0000000140018250     libucrt:lcidtoname_downlevel.obj
 0002:00004260       ??_C@_1M@MLKIBJOJ@?$AAe?$AAn?$AA?9?$AAP?$AAH@ 0000000140018260     libucrt:lcidtoname_downlevel.obj
 0002:00004270       ??_C@_1M@BDNIPEND@?$AAe?$AAs?$AA?9?$AAC?$AAL@ 0000000140018270     libucrt:lcidtoname_downlevel.obj
 0002:00004280       ??_C@_1M@MPNMEKBD@?$AAa?$AAr?$AA?9?$AAA?$AAE@ 0000000140018280     libucrt:lcidtoname_downlevel.obj
 0002:00004290       ??_C@_1M@KBJALCPI@?$AAe?$AAs?$AA?9?$AAU?$AAY@ 0000000140018290     libucrt:lcidtoname_downlevel.obj
 0002:000042a0       ??_C@_1M@LLCCOAGA@?$AAa?$AAr?$AA?9?$AAB?$AAH@ 00000001400182a0     libucrt:lcidtoname_downlevel.obj
 0002:000042b0       ??_C@_1M@PBFNCDEL@?$AAe?$AAs?$AA?9?$AAP?$AAY@ 00000001400182b0     libucrt:lcidtoname_downlevel.obj
 0002:000042c0       ??_C@_1M@EDGINPNP@?$AAa?$AAr?$AA?9?$AAQ?$AAA@ 00000001400182c0     libucrt:lcidtoname_downlevel.obj
 0002:000042d0       ??_C@_1M@MKDBIIJI@?$AAe?$AAs?$AA?9?$AAB?$AAO@ 00000001400182d0     libucrt:lcidtoname_downlevel.obj
 0002:000042e0       ??_C@_1M@CPKKEBLD@?$AAe?$AAs?$AA?9?$AAS?$AAV@ 00000001400182e0     libucrt:lcidtoname_downlevel.obj
 0002:000042f0       ??_C@_1M@NDBGMMJL@?$AAe?$AAs?$AA?9?$AAH?$AAN@ 00000001400182f0     libucrt:lcidtoname_downlevel.obj
 0002:00004300       ??_C@_1M@JIJIBHDP@?$AAe?$AAs?$AA?9?$AAN?$AAI@ 0000000140018300     libucrt:lcidtoname_downlevel.obj
 0002:00004310       ??_C@_1M@CGFMKEEK@?$AAe?$AAs?$AA?9?$AAP?$AAR@ 0000000140018310     libucrt:lcidtoname_downlevel.obj
 0002:00004320       ??_C@_1O@ICJHKIIK@?$AAz?$AAh?$AA?9?$AAC?$AAH?$AAT@ 0000000140018320     libucrt:lcidtoname_downlevel.obj
 0002:00004330       ??_C@_15CLNEJCE@?$AAs?$AAr@ 0000000140018330     libucrt:lcidtoname_downlevel.obj
 0002:00005180       ??_C@_1M@KAHEKEIG@?$AAa?$AAf?$AA?9?$AAz?$AAa@ 0000000140019180     libucrt:lcidtoname_downlevel.obj
 0002:00005190       ??_C@_1M@GIECOABL@?$AAa?$AAr?$AA?9?$AAa?$AAe@ 0000000140019190     libucrt:lcidtoname_downlevel.obj
 0002:000051a0       ??_C@_1M@BMLMEKGI@?$AAa?$AAr?$AA?9?$AAb?$AAh@ 00000001400191a0     libucrt:lcidtoname_downlevel.obj
 0002:000051b0       ??_C@_1M@DAPFDGGB@?$AAa?$AAr?$AA?9?$AAd?$AAz@ 00000001400191b0     libucrt:lcidtoname_downlevel.obj
 0002:000051c0       ??_C@_1M@FJNKGKIG@?$AAa?$AAr?$AA?9?$AAe?$AAg@ 00000001400191c0     libucrt:lcidtoname_downlevel.obj
 0002:000051d0       ??_C@_1M@FLGKKCLO@?$AAa?$AAr?$AA?9?$AAi?$AAq@ 00000001400191d0     libucrt:lcidtoname_downlevel.obj
 0002:000051e0       ??_C@_1M@GNDIPALM@?$AAa?$AAr?$AA?9?$AAj?$AAo@ 00000001400191e0     libucrt:lcidtoname_downlevel.obj
 0002:000051f0       ??_C@_1M@DDMJFMGJ@?$AAa?$AAr?$AA?9?$AAk?$AAw@ 00000001400191f0     libucrt:lcidtoname_downlevel.obj
 0002:00005200       ??_C@_1M@EJALMLHM@?$AAa?$AAr?$AA?9?$AAl?$AAb@ 0000000140019200     libucrt:lcidtoname_downlevel.obj
 0002:00005210       ??_C@_1M@MOBDBLOC@?$AAa?$AAr?$AA?9?$AAl?$AAy@ 0000000140019210     libucrt:lcidtoname_downlevel.obj
 0002:00005220       ??_C@_1M@JAOCLHDH@?$AAa?$AAr?$AA?9?$AAm?$AAa@ 0000000140019220     libucrt:lcidtoname_downlevel.obj
 0002:00005230       ??_C@_1M@JHPMKJIE@?$AAa?$AAr?$AA?9?$AAo?$AAm@ 0000000140019230     libucrt:lcidtoname_downlevel.obj
 0002:00005240       ??_C@_1M@OEPGHFNH@?$AAa?$AAr?$AA?9?$AAq?$AAa@ 0000000140019240     libucrt:lcidtoname_downlevel.obj
 0002:00005250       ??_C@_1M@KJDONENM@?$AAa?$AAr?$AA?9?$AAs?$AAa@ 0000000140019250     libucrt:lcidtoname_downlevel.obj
 0002:00005260       ??_C@_1M@DMJDKLKM@?$AAa?$AAr?$AA?9?$AAs?$AAy@ 0000000140019260     libucrt:lcidtoname_downlevel.obj
 0002:00005270       ??_C@_1M@OMFIPEDC@?$AAa?$AAr?$AA?9?$AAt?$AAn@ 0000000140019270     libucrt:lcidtoname_downlevel.obj
 0002:00005280       ??_C@_1M@IHMHGAON@?$AAa?$AAr?$AA?9?$AAy?$AAe@ 0000000140019280     libucrt:lcidtoname_downlevel.obj
 0002:00005290       ??_C@_1BG@KDCPGJGB@?$AAa?$AAz?$AA?9?$AAa?$AAz?$AA?9?$AAc?$AAy?$AAr?$AAl@ 0000000140019290     libucrt:lcidtoname_downlevel.obj
 0002:000052a8       ??_C@_1BG@IBCKDDOE@?$AAa?$AAz?$AA?9?$AAa?$AAz?$AA?9?$AAl?$AAa?$AAt?$AAn@ 00000001400192a8     libucrt:lcidtoname_downlevel.obj
 0002:000052c0       ??_C@_1M@EGPFDCPD@?$AAb?$AAe?$AA?9?$AAb?$AAy@ 00000001400192c0     libucrt:lcidtoname_downlevel.obj
 0002:000052d0       ??_C@_1M@PCMGMCGC@?$AAb?$AAg?$AA?9?$AAb?$AAg@ 00000001400192d0     libucrt:lcidtoname_downlevel.obj
 0002:000052e0       ??_C@_1M@BJBMFGOB@?$AAb?$AAn?$AA?9?$AAi?$AAn@ 00000001400192e0     libucrt:lcidtoname_downlevel.obj
 0002:000052f0       ??_C@_1BG@EAKMMACD@?$AAb?$AAs?$AA?9?$AAb?$AAa?$AA?9?$AAl?$AAa?$AAt?$AAn@ 00000001400192f0     libucrt:lcidtoname_downlevel.obj
 0002:00005308       ??_C@_1M@KGADAODK@?$AAc?$AAa?$AA?9?$AAe?$AAs@ 0000000140019308     libucrt:lcidtoname_downlevel.obj
 0002:00005318       ??_C@_1M@COAJPDHI@?$AAc?$AAs?$AA?9?$AAc?$AAz@ 0000000140019318     libucrt:lcidtoname_downlevel.obj
 0002:00005328       ??_C@_1M@DHBHFONH@?$AAc?$AAy?$AA?9?$AAg?$AAb@ 0000000140019328     libucrt:lcidtoname_downlevel.obj
 0002:00005338       ??_C@_1M@IMGKELGA@?$AAd?$AAa?$AA?9?$AAd?$AAk@ 0000000140019338     libucrt:lcidtoname_downlevel.obj
 0002:00005348       ??_C@_1M@NNDGDNGA@?$AAd?$AAe?$AA?9?$AAa?$AAt@ 0000000140019348     libucrt:lcidtoname_downlevel.obj
 0002:00005358       ??_C@_1M@IKDBHEEM@?$AAd?$AAe?$AA?9?$AAc?$AAh@ 0000000140019358     libucrt:lcidtoname_downlevel.obj
 0002:00005368       ??_C@_1M@GFFOJMCJ@?$AAd?$AAe?$AA?9?$AAd?$AAe@ 0000000140019368     libucrt:lcidtoname_downlevel.obj
 0002:00005378       ??_C@_1M@MDNLKBPM@?$AAd?$AAe?$AA?9?$AAl?$AAi@ 0000000140019378     libucrt:lcidtoname_downlevel.obj
 0002:00005388       ??_C@_1M@NJBEEJNL@?$AAd?$AAe?$AA?9?$AAl?$AAu@ 0000000140019388     libucrt:lcidtoname_downlevel.obj
 0002:00005398       ??_C@_1O@GNNELBAP@?$AAd?$AAi?$AAv?$AA?9?$AAm?$AAv@ 0000000140019398     libucrt:lcidtoname_downlevel.obj
 0002:000053a8       ??_C@_1M@EJLEOGAE@?$AAe?$AAl?$AA?9?$AAg?$AAr@ 00000001400193a8     libucrt:lcidtoname_downlevel.obj
 0002:000053b8       ??_C@_1M@GMPONJN@?$AAe?$AAn?$AA?9?$AAa?$AAu@ 00000001400193b8     libucrt:lcidtoname_downlevel.obj
 0002:000053c8       ??_C@_1M@NIDIIPGF@?$AAe?$AAn?$AA?9?$AAb?$AAz@ 00000001400193c8     libucrt:lcidtoname_downlevel.obj
 0002:000053d8       ??_C@_1M@JEHMIMFO@?$AAe?$AAn?$AA?9?$AAc?$AAa@ 00000001400193d8     libucrt:lcidtoname_downlevel.obj
 0002:000053e8       ??_C@_1M@IGMJCDLA@?$AAe?$AAn?$AA?9?$AAc?$AAb@ 00000001400193e8     libucrt:lcidtoname_downlevel.obj
 0002:000053f8       ??_C@_1M@BNFIGBKG@?$AAe?$AAn?$AA?9?$AAg?$AAb@ 00000001400193f8     libucrt:lcidtoname_downlevel.obj
 0002:00005408       ??_C@_1M@LKIFDIGP@?$AAe?$AAn?$AA?9?$AAi?$AAe@ 0000000140019408     libucrt:lcidtoname_downlevel.obj
 0002:00005418       ??_C@_1M@PJKFGCCO@?$AAe?$AAn?$AA?9?$AAj?$AAm@ 0000000140019418     libucrt:lcidtoname_downlevel.obj
 0002:00005428       ??_C@_1M@KPPKEPBO@?$AAe?$AAn?$AA?9?$AAn?$AAz@ 0000000140019428     libucrt:lcidtoname_downlevel.obj
 0002:00005438       ??_C@_1M@GMDGLDOB@?$AAe?$AAn?$AA?9?$AAp?$AAh@ 0000000140019438     libucrt:lcidtoname_downlevel.obj
 0002:00005448       ??_C@_1M@ONGIBJNA@?$AAe?$AAn?$AA?9?$AAt?$AAt@ 0000000140019448     libucrt:lcidtoname_downlevel.obj
 0002:00005458       ??_C@_1M@LLODPCMM@?$AAe?$AAn?$AA?9?$AAu?$AAs@ 0000000140019458     libucrt:lcidtoname_downlevel.obj
 0002:00005468       ??_C@_1M@LAKFNPAN@?$AAe?$AAn?$AA?9?$AAz?$AAa@ 0000000140019468     libucrt:lcidtoname_downlevel.obj
 0002:00005478       ??_C@_1M@MFNHNHEO@?$AAe?$AAn?$AA?9?$AAz?$AAw@ 0000000140019478     libucrt:lcidtoname_downlevel.obj
 0002:00005488       ??_C@_1M@EJEINPHM@?$AAe?$AAs?$AA?9?$AAa?$AAr@ 0000000140019488     libucrt:lcidtoname_downlevel.obj
 0002:00005498       ??_C@_1M@GNKPCCJA@?$AAe?$AAs?$AA?9?$AAb?$AAo@ 0000000140019498     libucrt:lcidtoname_downlevel.obj
 0002:000054a8       ??_C@_1M@LEEGFONL@?$AAe?$AAs?$AA?9?$AAc?$AAl@ 00000001400194a8     libucrt:lcidtoname_downlevel.obj
 0002:000054b8       ??_C@_1M@KGPDPBDF@?$AAe?$AAs?$AA?9?$AAc?$AAo@ 00000001400194b8     libucrt:lcidtoname_downlevel.obj
 0002:000054c8       ??_C@_1M@EIAHOHH@?$AAe?$AAs?$AA?9?$AAc?$AAr@ 00000001400194c8     libucrt:lcidtoname_downlevel.obj
 0002:000054d8       ??_C@_1M@LLPGMBIN@?$AAe?$AAs?$AA?9?$AAd?$AAo@ 00000001400194d8     libucrt:lcidtoname_downlevel.obj
 0002:000054e8       ??_C@_1M@DKHMKNJA@?$AAe?$AAs?$AA?9?$AAe?$AAc@ 00000001400194e8     libucrt:lcidtoname_downlevel.obj
 0002:000054f8       ??_C@_1M@GKGFPKAP@?$AAe?$AAs?$AA?9?$AAe?$AAs@ 00000001400194f8     libucrt:lcidtoname_downlevel.obj
 0002:00005508       ??_C@_1M@LKHKGDLN@?$AAe?$AAs?$AA?9?$AAg?$AAt@ 0000000140019508     libucrt:lcidtoname_downlevel.obj
 0002:00005518       ??_C@_1M@HEIIGGJD@?$AAe?$AAs?$AA?9?$AAh?$AAn@ 0000000140019518     libucrt:lcidtoname_downlevel.obj
 0002:00005528       ??_C@_1M@FBDHPPGD@?$AAe?$AAs?$AA?9?$AAm?$AAx@ 0000000140019528     libucrt:lcidtoname_downlevel.obj
 0002:00005538       ??_C@_1M@DPAGLNDH@?$AAe?$AAs?$AA?9?$AAn?$AAi@ 0000000140019538     libucrt:lcidtoname_downlevel.obj
 0002:00005548       ??_C@_1M@MDGOPGDD@?$AAe?$AAs?$AA?9?$AAp?$AAa@ 0000000140019548     libucrt:lcidtoname_downlevel.obj
 0002:00005558       ??_C@_1M@EMAMGBGE@?$AAe?$AAs?$AA?9?$AAp?$AAe@ 0000000140019558     libucrt:lcidtoname_downlevel.obj
 0002:00005568       ??_C@_1M@IBMCAOEC@?$AAe?$AAs?$AA?9?$AAp?$AAr@ 0000000140019568     libucrt:lcidtoname_downlevel.obj
 0002:00005578       ??_C@_1M@FGMDIJED@?$AAe?$AAs?$AA?9?$AAp?$AAy@ 0000000140019578     libucrt:lcidtoname_downlevel.obj
 0002:00005588       ??_C@_1M@IIDEOLLL@?$AAe?$AAs?$AA?9?$AAs?$AAv@ 0000000140019588     libucrt:lcidtoname_downlevel.obj
 0002:00005598       ??_C@_1M@GAOBIPA@?$AAe?$AAs?$AA?9?$AAu?$AAy@ 0000000140019598     libucrt:lcidtoname_downlevel.obj
 0002:000055a8       ??_C@_1M@JKFFICHJ@?$AAe?$AAs?$AA?9?$AAv?$AAe@ 00000001400195a8     libucrt:lcidtoname_downlevel.obj
 0002:000055b8       ??_C@_1M@PNMLOJDF@?$AAe?$AAt?$AA?9?$AAe?$AAe@ 00000001400195b8     libucrt:lcidtoname_downlevel.obj
 0002:000055c8       ??_C@_1M@GHHLIKEI@?$AAe?$AAu?$AA?9?$AAe?$AAs@ 00000001400195c8     libucrt:lcidtoname_downlevel.obj
 0002:000055d8       ??_C@_1M@PBNONODE@?$AAf?$AAa?$AA?9?$AAi?$AAr@ 00000001400195d8     libucrt:lcidtoname_downlevel.obj
 0002:000055e8       ??_C@_1M@JEEHPMIL@?$AAf?$AAi?$AA?9?$AAf?$AAi@ 00000001400195e8     libucrt:lcidtoname_downlevel.obj
 0002:000055f8       ??_C@_1M@LMDCNDBA@?$AAf?$AAo?$AA?9?$AAf?$AAo@ 00000001400195f8     libucrt:lcidtoname_downlevel.obj
 0002:00005608       ??_C@_1M@JKEOHLDK@?$AAf?$AAr?$AA?9?$AAb?$AAe@ 0000000140019608     libucrt:lcidtoname_downlevel.obj
 0002:00005618       ??_C@_1M@NOHADPMI@?$AAf?$AAr?$AA?9?$AAc?$AAa@ 0000000140019618     libucrt:lcidtoname_downlevel.obj
 0002:00005628       ??_C@_1M@KDHIHAEC@?$AAf?$AAr?$AA?9?$AAc?$AAh@ 0000000140019628     libucrt:lcidtoname_downlevel.obj
 0002:00005638       ??_C@_1M@MMBBFGAK@?$AAf?$AAr?$AA?9?$AAf?$AAr@ 0000000140019638     libucrt:lcidtoname_downlevel.obj
 0002:00005648       ??_C@_1M@PAFNENNF@?$AAf?$AAr?$AA?9?$AAl?$AAu@ 0000000140019648     libucrt:lcidtoname_downlevel.obj
 0002:00005658       ??_C@_1M@EOHDJGDD@?$AAf?$AAr?$AA?9?$AAm?$AAc@ 0000000140019658     libucrt:lcidtoname_downlevel.obj
 0002:00005668       ??_C@_1M@FAPLLOPF@?$AAg?$AAl?$AA?9?$AAe?$AAs@ 0000000140019668     libucrt:lcidtoname_downlevel.obj
 0002:00005678       ??_C@_1M@FOPBFLOO@?$AAg?$AAu?$AA?9?$AAi?$AAn@ 0000000140019678     libucrt:lcidtoname_downlevel.obj
 0002:00005688       ??_C@_1M@KBMCINPM@?$AAh?$AAe?$AA?9?$AAi?$AAl@ 0000000140019688     libucrt:lcidtoname_downlevel.obj
 0002:00005698       ??_C@_1M@BBPHKFPJ@?$AAh?$AAi?$AA?9?$AAi?$AAn@ 0000000140019698     libucrt:lcidtoname_downlevel.obj
 0002:000056a8       ??_C@_1M@PMBNDPHD@?$AAh?$AAr?$AA?9?$AAb?$AAa@ 00000001400196a8     libucrt:lcidtoname_downlevel.obj
 0002:000056b8       ??_C@_1M@BPCKOEGE@?$AAh?$AAr?$AA?9?$AAh?$AAr@ 00000001400196b8     libucrt:lcidtoname_downlevel.obj
 0002:000056c8       ??_C@_1M@GACBMHKE@?$AAh?$AAu?$AA?9?$AAh?$AAu@ 00000001400196c8     libucrt:lcidtoname_downlevel.obj
 0002:000056d8       ??_C@_1M@MILPAJJC@?$AAh?$AAy?$AA?9?$AAa?$AAm@ 00000001400196d8     libucrt:lcidtoname_downlevel.obj
 0002:000056e8       ??_C@_1M@BABBICEC@?$AAi?$AAd?$AA?9?$AAi?$AAd@ 00000001400196e8     libucrt:lcidtoname_downlevel.obj
 0002:000056f8       ??_C@_1M@BIKNHHPF@?$AAi?$AAs?$AA?9?$AAi?$AAs@ 00000001400196f8     libucrt:lcidtoname_downlevel.obj
 0002:00005708       ??_C@_1M@NMPCJPHE@?$AAi?$AAt?$AA?9?$AAc?$AAh@ 0000000140019708     libucrt:lcidtoname_downlevel.obj
 0002:00005718       ??_C@_1M@GHKGFEDF@?$AAi?$AAt?$AA?9?$AAi?$AAt@ 0000000140019718     libucrt:lcidtoname_downlevel.obj
 0002:00005728       ??_C@_1M@NIEJCJJA@?$AAj?$AAa?$AA?9?$AAj?$AAp@ 0000000140019728     libucrt:lcidtoname_downlevel.obj
 0002:00005738       ??_C@_1M@JILFNBIM@?$AAk?$AAa?$AA?9?$AAg?$AAe@ 0000000140019738     libucrt:lcidtoname_downlevel.obj
 0002:00005748       ??_C@_1M@PACPMGPH@?$AAk?$AAk?$AA?9?$AAk?$AAz@ 0000000140019748     libucrt:lcidtoname_downlevel.obj
 0002:00005758       ??_C@_1M@IELFGMHA@?$AAk?$AAn?$AA?9?$AAi?$AAn@ 0000000140019758     libucrt:lcidtoname_downlevel.obj
 0002:00005768       ??_C@_1O@IBBJHCH@?$AAk?$AAo?$AAk?$AA?9?$AAi?$AAn@ 0000000140019768     libucrt:lcidtoname_downlevel.obj
 0002:00005778       ??_C@_1M@DMHAEOGC@?$AAk?$AAo?$AA?9?$AAk?$AAr@ 0000000140019778     libucrt:lcidtoname_downlevel.obj
 0002:00005788       ??_C@_1M@HBAHBIGA@?$AAk?$AAy?$AA?9?$AAk?$AAg@ 0000000140019788     libucrt:lcidtoname_downlevel.obj
 0002:00005798       ??_C@_1M@KPMILCJG@?$AAl?$AAt?$AA?9?$AAl?$AAt@ 0000000140019798     libucrt:lcidtoname_downlevel.obj
 0002:000057a8       ??_C@_1M@BDEKKCA@?$AAl?$AAv?$AA?9?$AAl?$AAv@ 00000001400197a8     libucrt:lcidtoname_downlevel.obj
 0002:000057b8       ??_C@_1M@ELCKCCJJ@?$AAm?$AAi?$AA?9?$AAn?$AAz@ 00000001400197b8     libucrt:lcidtoname_downlevel.obj
 0002:000057c8       ??_C@_1M@CBOOLAPA@?$AAm?$AAk?$AA?9?$AAm?$AAk@ 00000001400197c8     libucrt:lcidtoname_downlevel.obj
 0002:000057d8       ??_C@_1M@GPHNBJKN@?$AAm?$AAl?$AA?9?$AAi?$AAn@ 00000001400197d8     libucrt:lcidtoname_downlevel.obj
 0002:000057e8       ??_C@_1M@PABJILIG@?$AAm?$AAn?$AA?9?$AAm?$AAn@ 00000001400197e8     libucrt:lcidtoname_downlevel.obj
 0002:000057f8       ??_C@_1M@FGBKKIPG@?$AAm?$AAr?$AA?9?$AAi?$AAn@ 00000001400197f8     libucrt:lcidtoname_downlevel.obj
 0002:00005808       ??_C@_1M@NDBPDDAL@?$AAm?$AAs?$AA?9?$AAb?$AAn@ 0000000140019808     libucrt:lcidtoname_downlevel.obj
 0002:00005818       ??_C@_1M@OPIHOOPI@?$AAm?$AAs?$AA?9?$AAm?$AAy@ 0000000140019818     libucrt:lcidtoname_downlevel.obj
 0002:00005828       ??_C@_1M@PPDBCNFM@?$AAm?$AAt?$AA?9?$AAm?$AAt@ 0000000140019828     libucrt:lcidtoname_downlevel.obj
 0002:00005838       ??_C@_1M@KDJDKMDD@?$AAn?$AAb?$AA?9?$AAn?$AAo@ 0000000140019838     libucrt:lcidtoname_downlevel.obj
 0002:00005848       ??_C@_1M@KFCFLMJP@?$AAn?$AAl?$AA?9?$AAb?$AAe@ 0000000140019848     libucrt:lcidtoname_downlevel.obj
 0002:00005858       ??_C@_1M@KPOPDDGO@?$AAn?$AAl?$AA?9?$AAn?$AAl@ 0000000140019858     libucrt:lcidtoname_downlevel.obj
 0002:00005868       ??_C@_1M@LJKPEMLN@?$AAn?$AAn?$AA?9?$AAn?$AAo@ 0000000140019868     libucrt:lcidtoname_downlevel.obj
 0002:00005878       ??_C@_1M@BDGHHBFL@?$AAn?$AAs?$AA?9?$AAz?$AAa@ 0000000140019878     libucrt:lcidtoname_downlevel.obj
 0002:00005888       ??_C@_1M@IDEHOAP@?$AAp?$AAa?$AA?9?$AAi?$AAn@ 0000000140019888     libucrt:lcidtoname_downlevel.obj
 0002:00005898       ??_C@_1M@HDBKGOGH@?$AAp?$AAl?$AA?9?$AAp?$AAl@ 0000000140019898     libucrt:lcidtoname_downlevel.obj
 0002:000058a8       ??_C@_1M@LJLLCMEH@?$AAp?$AAt?$AA?9?$AAb?$AAr@ 00000001400198a8     libucrt:lcidtoname_downlevel.obj
 0002:000058b8       ??_C@_1M@NCMONAAL@?$AAp?$AAt?$AA?9?$AAp?$AAt@ 00000001400198b8     libucrt:lcidtoname_downlevel.obj
 0002:000058c8       ??_C@_1O@EAKMAJDN@?$AAq?$AAu?$AAz?$AA?9?$AAb?$AAo@ 00000001400198c8     libucrt:lcidtoname_downlevel.obj
 0002:000058d8       ??_C@_1O@BHHPIGDN@?$AAq?$AAu?$AAz?$AA?9?$AAe?$AAc@ 00000001400198d8     libucrt:lcidtoname_downlevel.obj
 0002:000058e8       ??_C@_1O@GBAPEKMJ@?$AAq?$AAu?$AAz?$AA?9?$AAp?$AAe@ 00000001400198e8     libucrt:lcidtoname_downlevel.obj
 0002:000058f8       ??_C@_1M@CLGLEFBO@?$AAr?$AAo?$AA?9?$AAr?$AAo@ 00000001400198f8     libucrt:lcidtoname_downlevel.obj
 0002:00005908       ??_C@_1M@CEEDODME@?$AAr?$AAu?$AA?9?$AAr?$AAu@ 0000000140019908     libucrt:lcidtoname_downlevel.obj
 0002:00005918       ??_C@_1M@HPKKKMPP@?$AAs?$AAa?$AA?9?$AAi?$AAn@ 0000000140019918     libucrt:lcidtoname_downlevel.obj
 0002:00005928       ??_C@_1M@BKMAIGOJ@?$AAs?$AAe?$AA?9?$AAf?$AAi@ 0000000140019928     libucrt:lcidtoname_downlevel.obj
 0002:00005938       ??_C@_1M@NDPIFLFI@?$AAs?$AAe?$AA?9?$AAn?$AAo@ 0000000140019938     libucrt:lcidtoname_downlevel.obj
 0002:00005948       ??_C@_1M@DANKKHJ@?$AAs?$AAe?$AA?9?$AAs?$AAe@ 0000000140019948     libucrt:lcidtoname_downlevel.obj
 0002:00005958       ??_C@_1M@PNBLONPJ@?$AAs?$AAk?$AA?9?$AAs?$AAk@ 0000000140019958     libucrt:lcidtoname_downlevel.obj
 0002:00005968       ??_C@_1M@LFMODOAL@?$AAs?$AAl?$AA?9?$AAs?$AAi@ 0000000140019968     libucrt:lcidtoname_downlevel.obj
 0002:00005978       ??_C@_1O@DFKOMPG@?$AAs?$AAm?$AAa?$AA?9?$AAn?$AAo@ 0000000140019978     libucrt:lcidtoname_downlevel.obj
 0002:00005988       ??_C@_1O@NDKPBNNH@?$AAs?$AAm?$AAa?$AA?9?$AAs?$AAe@ 0000000140019988     libucrt:lcidtoname_downlevel.obj
 0002:00005998       ??_C@_1O@PLLKBHAB@?$AAs?$AAm?$AAj?$AA?9?$AAn?$AAo@ 0000000140019998     libucrt:lcidtoname_downlevel.obj
 0002:000059a8       ??_C@_1O@CLEPOGCA@?$AAs?$AAm?$AAj?$AA?9?$AAs?$AAe@ 00000001400199a8     libucrt:lcidtoname_downlevel.obj
 0002:000059b8       ??_C@_1O@DLGJGKMK@?$AAs?$AAm?$AAn?$AA?9?$AAf?$AAi@ 00000001400199b8     libucrt:lcidtoname_downlevel.obj
 0002:000059c8       ??_C@_1O@OJDJGAJC@?$AAs?$AAm?$AAs?$AA?9?$AAf?$AAi@ 00000001400199c8     libucrt:lcidtoname_downlevel.obj
 0002:000059d8       ??_C@_1M@BOFOGHPB@?$AAs?$AAq?$AA?9?$AAa?$AAl@ 00000001400199d8     libucrt:lcidtoname_downlevel.obj
 0002:000059e8       ??_C@_1BG@LJBBIPGB@?$AAs?$AAr?$AA?9?$AAb?$AAa?$AA?9?$AAc?$AAy?$AAr?$AAl@ 00000001400199e8     libucrt:lcidtoname_downlevel.obj
 0002:00005a00       ??_C@_1BG@JLBENFOE@?$AAs?$AAr?$AA?9?$AAb?$AAa?$AA?9?$AAl?$AAa?$AAt?$AAn@ 0000000140019a00     libucrt:lcidtoname_downlevel.obj
 0002:00005a18       ??_C@_1BG@KODPNHE@?$AAs?$AAr?$AA?9?$AAs?$AAp?$AA?9?$AAc?$AAy?$AAr?$AAl@ 0000000140019a18     libucrt:lcidtoname_downlevel.obj
 0002:00005a30       ??_C@_1BG@CIOGKHPB@?$AAs?$AAr?$AA?9?$AAs?$AAp?$AA?9?$AAl?$AAa?$AAt?$AAn@ 0000000140019a30     libucrt:lcidtoname_downlevel.obj
 0002:00005a48       ??_C@_1M@NGFJLMAC@?$AAs?$AAv?$AA?9?$AAf?$AAi@ 0000000140019a48     libucrt:lcidtoname_downlevel.obj
 0002:00005a58       ??_C@_1M@MPJEJAJC@?$AAs?$AAv?$AA?9?$AAs?$AAe@ 0000000140019a58     libucrt:lcidtoname_downlevel.obj
 0002:00005a68       ??_C@_1M@MPNDHLFK@?$AAs?$AAw?$AA?9?$AAk?$AAe@ 0000000140019a68     libucrt:lcidtoname_downlevel.obj
 0002:00005a78       ??_C@_1O@KOHBJJI@?$AAs?$AAy?$AAr?$AA?9?$AAs?$AAy@ 0000000140019a78     libucrt:lcidtoname_downlevel.obj
 0002:00005a88       ??_C@_1M@LDCEFHA@?$AAt?$AAa?$AA?9?$AAi?$AAn@ 0000000140019a88     libucrt:lcidtoname_downlevel.obj
 0002:00005a98       ??_C@_1M@CNJOFAK@?$AAt?$AAe?$AA?9?$AAi?$AAn@ 0000000140019a98     libucrt:lcidtoname_downlevel.obj
 0002:00005aa8       ??_C@_1M@GNAECACD@?$AAt?$AAh?$AA?9?$AAt?$AAh@ 0000000140019aa8     libucrt:lcidtoname_downlevel.obj
 0002:00005ab8       ??_C@_1M@CHBIHOJO@?$AAt?$AAn?$AA?9?$AAz?$AAa@ 0000000140019ab8     libucrt:lcidtoname_downlevel.obj
 0002:00005ac8       ??_C@_1M@GCCMIGPJ@?$AAt?$AAr?$AA?9?$AAt?$AAr@ 0000000140019ac8     libucrt:lcidtoname_downlevel.obj
 0002:00005ad8       ??_C@_1M@CELMCNBK@?$AAt?$AAt?$AA?9?$AAr?$AAu@ 0000000140019ad8     libucrt:lcidtoname_downlevel.obj
 0002:00005ae8       ??_C@_1M@KLMCELGA@?$AAu?$AAk?$AA?9?$AAu?$AAa@ 0000000140019ae8     libucrt:lcidtoname_downlevel.obj
 0002:00005af8       ??_C@_1M@EPAJJAJF@?$AAu?$AAr?$AA?9?$AAp?$AAk@ 0000000140019af8     libucrt:lcidtoname_downlevel.obj
 0002:00005b08       ??_C@_1BG@GEGPMCDJ@?$AAu?$AAz?$AA?9?$AAu?$AAz?$AA?9?$AAc?$AAy?$AAr?$AAl@ 0000000140019b08     libucrt:lcidtoname_downlevel.obj
 0002:00005b20       ??_C@_1BG@EGGKJILM@?$AAu?$AAz?$AA?9?$AAu?$AAz?$AA?9?$AAl?$AAa?$AAt?$AAn@ 0000000140019b20     libucrt:lcidtoname_downlevel.obj
 0002:00005b38       ??_C@_1M@GFOCLFF@?$AAv?$AAi?$AA?9?$AAv?$AAn@ 0000000140019b38     libucrt:lcidtoname_downlevel.obj
 0002:00005b48       ??_C@_1M@CPAMEDFI@?$AAx?$AAh?$AA?9?$AAz?$AAa@ 0000000140019b48     libucrt:lcidtoname_downlevel.obj
 0002:00005b58       ??_C@_1O@EBKIFIGN@?$AAz?$AAh?$AA?9?$AAc?$AAh?$AAs@ 0000000140019b58     libucrt:lcidtoname_downlevel.obj
 0002:00005b68       ??_C@_1O@NMHPGANE@?$AAz?$AAh?$AA?9?$AAc?$AAh?$AAt@ 0000000140019b68     libucrt:lcidtoname_downlevel.obj
 0002:00005b78       ??_C@_1M@LPINJOMC@?$AAz?$AAh?$AA?9?$AAc?$AAn@ 0000000140019b78     libucrt:lcidtoname_downlevel.obj
 0002:00005b88       ??_C@_1M@OCJEJODD@?$AAz?$AAh?$AA?9?$AAh?$AAk@ 0000000140019b88     libucrt:lcidtoname_downlevel.obj
 0002:00005b98       ??_C@_1M@DNDLJINH@?$AAz?$AAh?$AA?9?$AAm?$AAo@ 0000000140019b98     libucrt:lcidtoname_downlevel.obj
 0002:00005ba8       ??_C@_1M@MBFDNDND@?$AAz?$AAh?$AA?9?$AAs?$AAg@ 0000000140019ba8     libucrt:lcidtoname_downlevel.obj
 0002:00005bb8       ??_C@_1M@IMEPLEPE@?$AAz?$AAh?$AA?9?$AAt?$AAw@ 0000000140019bb8     libucrt:lcidtoname_downlevel.obj
 0002:00005bc8       ??_C@_1M@BBGHNHJP@?$AAz?$AAu?$AA?9?$AAz?$AAa@ 0000000140019bc8     libucrt:lcidtoname_downlevel.obj
 0002:00005e30       ??_C@_1BA@BALFACEM@?$AAC?$AAO?$AAN?$AAO?$AAU?$AAT?$AA$@ 0000000140019e30     libucrt:initcon.obj
 0002:00005e40       __log10_256_lead           0000000140019e40     libucrt:log10_256_lead_tail_table.obj
 0002:00006650       __log10_256_tail           000000014001a650     libucrt:log10_256_lead_tail_table.obj
 0002:00006e60       __log_F_inv_qword          000000014001ae60     libucrt:log_f_inv_qword_table.obj
 0002:00007670       ??_C@_05HGHHAHAP@log10@    000000014001b670     libucrt:log_special.obj
 0002:00007690       ??_C@_1CC@GHMGMOKH@?$AAS?$AAo?$AAf?$AAt?$AAw?$AAa?$AAr?$AAe?$AA?2?$AAC?$AAl?$AAa?$AAs?$AAs?$AAe@ 000000014001b690     FileProtocolHandler.obj
 0002:000076b8       ??_C@_1CG@CBEOMECC@?$AAs?$AAh?$AAe?$AAl?$AAl?$AA?2?$AAo?$AAp?$AAe?$AAn?$AA?2?$AAc?$AAo?$AAm?$AAm@ 000000014001b6b8     FileProtocolHandler.obj
 0002:000076e0       ??_C@_13FPGAJAPJ@?$AA?2@   000000014001b6e0     FileProtocolHandler.obj
 0002:000076e4       ??_C@_13EBCNDICG@?$AA?3@   000000014001b6e4     FileProtocolHandler.obj
 0002:000076e8       ??_C@_15EAJGFGNH@?$AA?1?$AA?1@ 000000014001b6e8     FileProtocolHandler.obj
 0002:000076f0       ??_C@_19BDAJEHDN@?$AAo?$AAp?$AAe?$AAn@ 000000014001b6f0     FileProtocolHandler.obj
 0002:00007700       ??_C@_19LBFNCNHD@?$AA?$CC?$AA?5?$AA?$CF?$AA1@ 000000014001b700     FileProtocolHandler.obj
 0002:00007710       ??_C@_1DC@GIJHMEGF@?$AAU?$AAR?$AAL?$AA?3?$AA?5?$AAF?$AAi?$AAl?$AAe?$AAP?$AAr?$AAo?$AAt?$AAo?$AAc@ 000000014001b710     FileProtocolHandler.obj
 0002:00007748       ??_C@_1BK@IBPJPEFD@?$AAU?$AAR?$AAL?$AA?5?$AAP?$AAr?$AAo?$AAt?$AAo?$AAc?$AAo?$AAl@ 000000014001b748     FileProtocolHandler.obj
 0002:00007768       ??_C@_1M@DMKIBEPF@?$AA?6?$AA?$AG?$AA1?$AA?3?$AA?5@ 000000014001b768     FileProtocolHandler.obj
 0002:00007778       ??_C@_1BM@FMJBCPGK@?$AA?4?$AAp?$AAr?$AAo?$AAt?$AAo?$AAc?$AAo?$AAl?$AAn?$AAa?$AAm?$AAe@ 000000014001b778     FileProtocolHandler.obj
 0002:00007794       ??_C@_13BPINEIPE@?$AAr@    000000014001b794     FileProtocolHandler.obj
 0002:00007798       ??_C@_1DA@JDJINELL@?$AAS?$AAh?$AAe?$AAl?$AAl?$AAE?$AAx?$AAe?$AAc?$AAu?$AAt?$AAe?$AAE?$AAx?$AAk@ 000000014001b798     FileProtocolHandler.obj
 0002:000077c8       ??_C@_13OFJNNHOA@?$AA?$GA@ 000000014001b7c8     FileProtocolHandler.obj
 0002:000077d0       ??_C@_1CA@NAFLDBOK@?$PP?W?$PP?m?$PP?$LA?$PP?i?$PP?$OA?$AA?$BF?$AAp?$AAL?$AA?$AN?$AAc?$AAg?$AAY?$AA?$AC?$AA?3?$AA?$GA@ 000000014001b7d0     FileProtocolHandler.obj
 0002:000077f0       ??_C@_1CI@ELEPDEII@?$PP?l?$PP?$LI?$PP?$LJ?$PP?H?$PP?j?$AAn?$PP?$KN?$AA?$HP?$PP?x?$AAM?$AAk?$AA1?$AAW?$AAW?$AA?$HO@ 000000014001b7f0     FileProtocolHandler.obj
 0002:00007818       ??_C@_1DG@JDENJJKJ@?$AA?$AL?$AA?$BI?$AAn?$PP?$LD?$PP?$NO?$PP?s?$PP?I?$AAg?$AA?$HL?$AA2?$AAU?$PP?$IM?$AAf?$AAD?$AA?$HO@ 000000014001b818     FileProtocolHandler.obj
 0002:00007850       ??_C@_1BG@MICDDFAA@?$PP?c?$AAd?$AAk?$AA1?$AAW?$AAW?$AA?$HO?$AAW?$AA_?$AA?$AC@ 000000014001b850     FileProtocolHandler.obj
 0002:00007868       ??_C@_1BG@KOIGGLJK@?$AA?$HL?$AA2?$AAk?$AA1?$AAW?$AAW?$AA?$HO?$AAW?$AA_?$AA?$AC@ 000000014001b868     FileProtocolHandler.obj
 0002:00007880       ??_C@_1BO@FDIBLEN@?$PP?W?$PP?m?$PP?H?$PP?$LD?$PP?k?$AA?$AN?$AAL?$AA?$AN?$AAc?$AAg?$AAY?$AA?$AC?$AA?3?$AA?$GA@ 000000014001b880     FileProtocolHandler.obj
 0002:000078a0       ??_C@_0BA@JFNIOLAK@string?5too?5long@ 000000014001b8a0     FileProtocolHandler.obj
 0002:00007a40       __xmm@00000000000000070000000000000000 000000014001ba40     FileProtocolHandler.obj
 0002:00007ac0       _load_config_used          000000014001bac0     LIBCMT:loadcfg.obj
 0002:00007bc0       ??_R4exception@std@@6B@    000000014001bbc0     libcpmt:xthrow.obj
 0002:00007be8       ??_R3exception@std@@8      000000014001bbe8     libcpmt:xthrow.obj
 0002:00007c00       ??_R2exception@std@@8      000000014001bc00     libcpmt:xthrow.obj
 0002:00007c10       ??_R1A@?0A@EA@exception@std@@8 000000014001bc10     libcpmt:xthrow.obj
 0002:00007c38       ??_R4bad_alloc@std@@6B@    000000014001bc38     libcpmt:xthrow.obj
 0002:00007c60       ??_R3bad_alloc@std@@8      000000014001bc60     libcpmt:xthrow.obj
 0002:00007c78       ??_R2bad_alloc@std@@8      000000014001bc78     libcpmt:xthrow.obj
 0002:00007c90       ??_R1A@?0A@EA@bad_alloc@std@@8 000000014001bc90     libcpmt:xthrow.obj
 0002:00007cb8       ??_R4logic_error@std@@6B@  000000014001bcb8     libcpmt:xthrow.obj
 0002:00007ce0       ??_R3logic_error@std@@8    000000014001bce0     libcpmt:xthrow.obj
 0002:00007cf8       ??_R2logic_error@std@@8    000000014001bcf8     libcpmt:xthrow.obj
 0002:00007d10       ??_R1A@?0A@EA@logic_error@std@@8 000000014001bd10     libcpmt:xthrow.obj
 0002:00007d38       ??_R4length_error@std@@6B@ 000000014001bd38     libcpmt:xthrow.obj
 0002:00007d60       ??_R3length_error@std@@8   000000014001bd60     libcpmt:xthrow.obj
 0002:00007d78       ??_R2length_error@std@@8   000000014001bd78     libcpmt:xthrow.obj
 0002:00007d98       ??_R1A@?0A@EA@length_error@std@@8 000000014001bd98     libcpmt:xthrow.obj
 0002:00007dc0       ??_R4type_info@@6B@        000000014001bdc0     LIBCMT:std_type_info_static.obj
 0002:00007de8       ??_R3type_info@@8          000000014001bde8     LIBCMT:std_type_info_static.obj
 0002:00007e00       ??_R2type_info@@8          000000014001be00     LIBCMT:std_type_info_static.obj
 0002:00007e10       ??_R1A@?0A@EA@type_info@@8 000000014001be10     LIBCMT:std_type_info_static.obj
 0002:00007e38       ??_R4bad_array_new_length@std@@6B@ 000000014001be38     LIBCMT:throw_bad_alloc.obj
 0002:00007e60       ??_R3bad_array_new_length@std@@8 000000014001be60     LIBCMT:throw_bad_alloc.obj
 0002:00007e78       ??_R2bad_array_new_length@std@@8 000000014001be78     LIBCMT:throw_bad_alloc.obj
 0002:00007e98       ??_R1A@?0A@EA@bad_array_new_length@std@@8 000000014001be98     LIBCMT:throw_bad_alloc.obj
 0002:00007ec0       ??_R4bad_exception@std@@6B@ 000000014001bec0     libvcruntime:frame.obj
 0002:00007ee8       ??_R3bad_exception@std@@8  000000014001bee8     libvcruntime:frame.obj
 0002:00007f00       ??_R2bad_exception@std@@8  000000014001bf00     libvcruntime:frame.obj
 0002:00007f18       ??_R1A@?0A@EA@bad_exception@std@@8 000000014001bf18     libvcruntime:frame.obj
 0002:00008288       __rtc_iaa                  000000014001c288     LIBCMT:initsect.obj
 0002:00008290       __rtc_izz                  000000014001c290     LIBCMT:initsect.obj
 0002:00008298       __rtc_taa                  000000014001c298     LIBCMT:initsect.obj
 0002:000082a0       __rtc_tzz                  000000014001c2a0     LIBCMT:initsect.obj
 0002:000097c8       _TI2?AVbad_alloc@std@@     000000014001d7c8     libcpmt:xthrow.obj
 0002:000097e8       _CTA2?AVbad_alloc@std@@    000000014001d7e8     libcpmt:xthrow.obj
 0002:00009800       _CT??_R0?AVbad_alloc@std@@@8??0bad_alloc@std@@QEAA@AEBV01@@Z24 000000014001d800     libcpmt:xthrow.obj
 0002:00009828       _CT??_R0?AVexception@std@@@8??0exception@std@@QEAA@AEBV01@@Z24 000000014001d828     libcpmt:xthrow.obj
 0002:00009850       _CT??_R0?AVlogic_error@std@@@8??0logic_error@std@@QEAA@AEBV01@@Z24 000000014001d850     libcpmt:xthrow.obj
 0002:00009878       _TI3?AVlength_error@std@@  000000014001d878     libcpmt:xthrow.obj
 0002:00009898       _CTA3?AVlength_error@std@@ 000000014001d898     libcpmt:xthrow.obj
 0002:000098b8       _CT??_R0?AVlength_error@std@@@8??0length_error@std@@QEAA@AEBV01@@Z24 000000014001d8b8     libcpmt:xthrow.obj
 0002:000098e0       _TI3?AVbad_array_new_length@std@@ 000000014001d8e0     LIBCMT:throw_bad_alloc.obj
 0002:00009900       _CTA3?AVbad_array_new_length@std@@ 000000014001d900     LIBCMT:throw_bad_alloc.obj
 0002:00009920       _CT??_R0?AVbad_array_new_length@std@@@8??0bad_array_new_length@std@@QEAA@AEBV01@@Z24 000000014001d920     LIBCMT:throw_bad_alloc.obj
 0002:00009948       _TI2?AVbad_exception@std@@ 000000014001d948     libvcruntime:frame.obj
 0002:00009968       _CTA2?AVbad_exception@std@@ 000000014001d968     libvcruntime:frame.obj
 0002:00009980       _CT??_R0?AVbad_exception@std@@@8??0bad_exception@std@@QEAA@AEBV01@@Z24 000000014001d980     libvcruntime:frame.obj
 0002:000099a4       __IMPORT_DESCRIPTOR_KERNEL32 000000014001d9a4     kernel32:KERNEL32.dll
 0002:000099b8       __IMPORT_DESCRIPTOR_USER32 000000014001d9b8     user32:USER32.dll
 0002:000099cc       __IMPORT_DESCRIPTOR_ADVAPI32 000000014001d9cc     advapi32:ADVAPI32.dll
 0002:000099e0       __IMPORT_DESCRIPTOR_SHELL32 000000014001d9e0     shell32:SHELL32.dll
 0002:000099f4       __IMPORT_DESCRIPTOR_SHLWAPI 000000014001d9f4     shlwapi:SHLWAPI.dll
 0002:00009a08       __NULL_IMPORT_DESCRIPTOR   000000014001da08     kernel32:KERNEL32.dll
 0003:00000000       __security_cookie_complement 000000014001f000     LIBCMT:gs_cookie.obj
 0003:00000008       __security_cookie          000000014001f008     LIBCMT:gs_cookie.obj
 0003:00000010       __scrt_native_dllmain_reason 000000014001f010     LIBCMT:utility.obj
 0003:00000014       __scrt_default_matherr     000000014001f014     LIBCMT:matherr.obj
 0003:00000018       __isa_available            000000014001f018     LIBCMT:cpu_disp.obj
 0003:0000001c       __isa_enabled              000000014001f01c     LIBCMT:cpu_disp.obj
 0003:00000020       __memcpy_nt_iters          000000014001f020     LIBCMT:cpu_disp.obj
 0003:00000040       __abort_behavior           000000014001f040     libucrt:abort.obj
 0003:00000060       _iob                       000000014001f060     libucrt:_file.obj
 0003:00000170       __acrt_initial_locale_data 000000014001f170     libucrt:nlsdata.obj
 0003:000002c8       __acrt_initial_locale_pointers 000000014001f2c8     libucrt:nlsdata.obj
 0003:000002d8       __acrt_wide_c_locale_string 000000014001f2d8     libucrt:nlsdata.obj
 0003:000002e0       __badioinfo                000000014001f2e0     libucrt:ioinit.obj
 0003:00000328       _pwctype                   000000014001f328     libucrt:ctype.obj
 0003:00000330       __acrt_initial_multibyte_data 000000014001f330     libucrt:mbctype.obj
 0003:00000870       __acrt_lconv_c             000000014001f870     libucrt:localeconv.obj
 0003:00000908       __acrt_lconv_static_decimal 000000014001f908     libucrt:localeconv.obj
 0003:0000090c       __acrt_lconv_static_W_decimal 000000014001f90c     libucrt:localeconv.obj
 0003:00000910       __globallocalestatus       000000014001f910     libucrt:glstatus.obj
 0003:00000920       _lookuptrailbytes          000000014001f920     libucrt:read.obj
 0003:00000a40       _fltused                   000000014001fa40     LIBCMT:fltused.obj
 0003:00000a50       ?szProtocolName@@3PA_WA    000000014001fa50     FileProtocolHandler.obj
 0003:00000ad0       ??_R0?AVbad_alloc@std@@@8  000000014001fad0     libcpmt:xthrow.obj
 0003:00000af8       ??_R0?AVexception@std@@@8  000000014001faf8     libcpmt:xthrow.obj
 0003:00000b20       ??_R0?AVlogic_error@std@@@8 000000014001fb20     libcpmt:xthrow.obj
 0003:00000b48       ??_R0?AVlength_error@std@@@8 000000014001fb48     libcpmt:xthrow.obj
 0003:00000b70       ??_R0?AVtype_info@@@8      000000014001fb70     LIBCMT:std_type_info_static.obj
 0003:00000b90       ??_R0?AVbad_array_new_length@std@@@8 000000014001fb90     LIBCMT:throw_bad_alloc.obj
 0003:00000bc0       ??_R0?AVbad_exception@std@@@8 000000014001fbc0     libvcruntime:frame.obj
 0003:00001160       __scrt_current_native_startup_state 0000000140020160     LIBCMT:utility.obj
 0003:00001168       __scrt_native_startup_lock 0000000140020168     LIBCMT:utility.obj
 0003:000011b0       ?__type_info_root_node@@3U__type_info_node@@A 00000001400201b0     LIBCMT:tncleanup.obj
 0003:000011c0       ?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA 00000001400201c0     LIBCMT:default_local_stdio_options.obj
 0003:000011c8       ?_OptionsStorage@?1??__local_stdio_scanf_options@@9@4_KA 00000001400201c8     LIBCMT:default_local_stdio_options.obj
 0003:000011d0       __scrt_debugger_hook_flag  00000001400201d0     LIBCMT:utility_desktop.obj
 0003:000011d4       __favor                    00000001400201d4     LIBCMT:cpu_disp.obj
 0003:000011d8       ?__WinRTOutOfMemoryExceptionCallback@@3P6APEAXXZEA 00000001400201d8     libvcruntime:ehhelpers.obj
 0003:000012e0       __pPurecall                00000001400202e0     libvcruntime:purevirt_data.obj
 0003:000012e8       ?pArgList@UnDecorator@@0PEAVReplicator@@EA 00000001400202e8     libvcruntime:undname.obj
 0003:000012f0       ?pZNameList@UnDecorator@@0PEAVReplicator@@EA 00000001400202f0     libvcruntime:undname.obj
 0003:000012f8       ?pTemplateArgList@UnDecorator@@0PEAVReplicator@@EA 00000001400202f8     libvcruntime:undname.obj
 0003:00001300       ?gName@UnDecorator@@0PEBDEB 0000000140020300     libvcruntime:undname.obj
 0003:00001308       ?name@UnDecorator@@0PEBDEB 0000000140020308     libvcruntime:undname.obj
 0003:00001310       ?disableFlags@UnDecorator@@0KA 0000000140020310     libvcruntime:undname.obj
 0003:00001314       ?fExplicitTemplateParams@UnDecorator@@0_NA 0000000140020314     libvcruntime:undname.obj
 0003:00001315       ?fGetTemplateArgumentList@UnDecorator@@0_NA 0000000140020315     libvcruntime:undname.obj
 0003:00001318       ?m_pGetParameter@UnDecorator@@0P6APEADJ@ZEA 0000000140020318     libvcruntime:undname.obj
 0003:00001320       ?m_CHPENameOffset@UnDecorator@@0KA 0000000140020320     libvcruntime:undname.obj
 0003:00001324       ?m_recursionLevel@UnDecorator@@0KA 0000000140020324     libvcruntime:undname.obj
 0003:00001580       _environ_table             0000000140020580     libucrt:environment_initialization.obj
 0003:00001588       _wenviron_table            0000000140020588     libucrt:environment_initialization.obj
 0003:00001590       __dcrt_initial_wide_environment 0000000140020590     libucrt:environment_initialization.obj
 0003:00001598       __dcrt_initial_narrow_environment 0000000140020598     libucrt:environment_initialization.obj
 0003:000015b0       ?c_exit_complete@?1???R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ@4_NA 00000001400205b0     libucrt:exit.obj
 0003:000015b4       __acrt_locale_changed_data 00000001400205b4     libucrt:wsetlocale.obj
 0003:000015bc       _commode                   00000001400205bc     libucrt:ncommode.obj
 0003:000015c0       __acrt_atexit_table        00000001400205c0     libucrt:onexit.obj
 0003:000015d8       __acrt_at_quick_exit_table 00000001400205d8     libucrt:onexit.obj
 0003:000015f0       _nstream                   00000001400205f0     libucrt:_file.obj
 0003:000015f8       __piob                     00000001400205f8     libucrt:_file.obj
 0003:00001600       _cflush                    0000000140020600     libucrt:_file.obj
 0003:00001608       __acrt_current_locale_data 0000000140020608     libucrt:nlsdata.obj
 0003:00001610       __pioinfo                  0000000140020610     libucrt:ioinit.obj
 0003:00001a10       _nhandle                   0000000140020a10     libucrt:ioinit.obj
 0003:00001c58       _mbctype                   0000000140020c58     libucrt:mbctype.obj
 0003:00001c60       _mbcasemap                 0000000140020c60     libucrt:mbctype.obj
 0003:00001c68       __acrt_current_multibyte_data 0000000140020c68     libucrt:mbctype.obj
 0003:00001c78       _wpgmptr                   0000000140020c78     libucrt:argv_data.obj
 0003:00001c80       __argc                     0000000140020c80     libucrt:argv_data.obj
 0003:00001c88       __argv                     0000000140020c88     libucrt:argv_data.obj
 0003:00001c90       __wargv                    0000000140020c90     libucrt:argv_data.obj
 0003:00001c98       _acmdln                    0000000140020c98     libucrt:argv_data.obj
 0003:00001ca0       _wcmdln                    0000000140020ca0     libucrt:argv_data.obj
 0003:00001ca8       _fmode                     0000000140020ca8     libucrt:txtmode.obj
 0003:00001e60       __acrt_lconv_static_null   0000000140020e60     libucrt:localeconv.obj
 0003:00001e64       __acrt_lconv_static_W_null 0000000140020e64     libucrt:localeconv.obj
 0003:00001e68       __acrt_heap                0000000140020e68     libucrt:heap_handle.obj
 0003:00001e90       __acrt_stdout_buffer       0000000140020e90     libucrt:_sftbuf.obj
 0003:00001e98       __acrt_stderr_buffer       0000000140020e98     libucrt:_sftbuf.obj
 0003:00001ea8       _umaskval                  0000000140020ea8     libucrt:umask.obj
 0003:00001eb8       __fma3_is_available        0000000140020eb8     libucrt:fma3_available.obj
 0003:00001ebc       __use_fma3_lib             0000000140020ebc     libucrt:fma3_available.obj
 0003:00001ec0       ?hInst@@3PEAUHINSTANCE__@@EA 0000000140020ec0     FileProtocolHandler.obj
 0003:00001ed0       ?szWindowClass@@3PA_WA     0000000140020ed0     FileProtocolHandler.obj
 0003:00001fa0       ?szTitle@@3PA_WA           0000000140020fa0     FileProtocolHandler.obj
 0003:00002070       __scrt_ucrt_dll_is_in_use  0000000140021070     <common>
 0003:00002078       __dyn_tls_dtor_callback    0000000140021078     <common>
 0003:00002080       __dyn_tls_init_callback    0000000140021080     <common>

 entry point at        0001:0000333c

 Static symbols

 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     user32:USER32.dll
 0000:fffc3000       .debug$S                   0000000140000000     advapi32:ADVAPI32.dll
 0000:fffc3000       .debug$S                   0000000140000000     advapi32:ADVAPI32.dll
 0000:fffc3000       .debug$S                   0000000140000000     advapi32:ADVAPI32.dll
 0000:fffc3000       .debug$S                   0000000140000000     advapi32:ADVAPI32.dll
 0000:fffc3000       .debug$S                   0000000140000000     advapi32:ADVAPI32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     shell32:SHELL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     shlwapi:SHLWAPI.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     shlwapi:SHLWAPI.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     shlwapi:SHLWAPI.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0000:fffc3000       .debug$S                   0000000140000000     kernel32:KERNEL32.dll
 0001:00000000       ?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 0000000140001000 f   FileProtocolHandler.obj
 0001:00000100       ?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 0000000140001100 f   FileProtocolHandler.obj
 0001:00000310       ?OpenFile@CFileProtocolHandlerService@?A0x9219411d@@QEAAJPEB_W@Z 0000000140001310 f   FileProtocolHandler.obj
 0001:000006c0       ?<lambda_invoker_cdecl>@<lambda_1350e090c1767e0d7e74fd51cceb431d>@@CAHPEAUHWND__@@_J@Z 00000001400016c0 f   FileProtocolHandler.obj
 0001:00000700       ?ProtocolName@CFileProtocolHandlerService@?A0x9219411d@@QEBA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 0000000140001700 f   FileProtocolHandler.obj
 0001:00000810       ?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 0000000140001810 f   FileProtocolHandler.obj
 0001:000008e0       ?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 00000001400018e0 f   FileProtocolHandler.obj
 0001:00000e60       ?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 0000000140001e60 f   FileProtocolHandler.obj
 0001:00001100       ?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 0000000140002100 f   FileProtocolHandler.obj
 0001:000017d0       ?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 00000001400027d0 f   FileProtocolHandler.obj
 0001:00002dd0       $$000000                   0000000140003dd0     LIBCMT:amdsecgs.obj
 0001:00002fbc       capture_current_context    0000000140003fbc f   LIBCMT:gs_report.obj
 0001:0000302c       capture_previous_context   000000014000402c f   LIBCMT:gs_report.obj
 0001:000030e4       ?pre_c_initialization@@YAHXZ 00000001400040e4 f   LIBCMT:exe_wwinmain.obj
 0001:0000319c       ?post_pgo_initialization@@YAHXZ 000000014000419c f   LIBCMT:exe_wwinmain.obj
 0001:000031ac       ?pre_cpp_initialization@@YAXXZ 00000001400041ac f   LIBCMT:exe_wwinmain.obj
 0001:000031c8       ?__scrt_common_main_seh@@YAHXZ 00000001400041c8 f   LIBCMT:exe_wwinmain.obj
 0001:000037a8       report_memory_leaks        00000001400047a8 f   libucrt:initialization.obj
 0001:000037a8       uninitialize_c             00000001400047a8 f   libucrt:initialization.obj
 0001:000037a8       initialize_environment     00000001400047a8 f   libucrt:initialization.obj
 0001:000037a8       initialize_global_state_isolation 00000001400047a8 f   libucrt:initialization.obj
 0001:000037a8       uninitialize_global_state_isolation 00000001400047a8 f   libucrt:initialization.obj
 0001:00004750       $$000000                   0000000140005750     libvcruntime:memset.obj
 0001:0000484c       MsetTab                    000000014000584c     libvcruntime:memset.obj
 0001:00004b9c       ??$BuildCatchObjectHelperInternal@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 0000000140005b9c f   libvcruntime:frame.obj
 0001:00004d9c       ??$BuildCatchObjectInternal@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 0000000140005d9c f   libvcruntime:frame.obj
 0001:00004e5c       ??$CatchIt@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@PEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_TryBlockMapEntry@@H1EE@Z 0000000140005e5c f   libvcruntime:frame.obj
 0001:00004f2c       ??$FindHandler@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@EH1@Z 0000000140005f2c f   libvcruntime:frame.obj
 0001:00005390       ??$FindHandlerForForeignException@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@HH1@Z 0000000140006390 f   libvcruntime:frame.obj
 0001:00005b98       ?ExFilterRethrow@@YAHPEAU_EXCEPTION_POINTERS@@PEAUEHExceptionRecord@@PEAH@Z 0000000140006b98 f   libvcruntime:frame.obj
 0001:00005e4c       ?IsInExceptionSpec@@YAEPEAUEHExceptionRecord@@PEBU_s_ESTypeList@@@Z 0000000140006e4c f   libvcruntime:frame.obj
 0001:00005f24       ?Is_bad_exception_allowed@@YAEPEBU_s_ESTypeList@@@Z 0000000140006f24 f   libvcruntime:frame.obj
 0001:00005fe0       $$000000                   0000000140006fe0     libvcruntime:notify.obj
 0001:000060dc       ?try_get_function@@YAPEAXW4function_id@?A0x14c33c87@@QEBDQEBW4module_id@2@2@Z 00000001400070dc f   libvcruntime:winapi_downlevel.obj
 0001:000064d0       $$000000                   00000001400074d0     libvcruntime:handlers.obj
 0001:00006580       $$000000                   0000000140007580     libvcruntime:memcpy.obj
 0001:00006637       MoveSmall                  0000000140007637     libvcruntime:memcpy.obj
 0001:000069d8       ??$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z 00000001400079d8 f   libucrt:fopen.obj
 0001:00006ce4       ??$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z 0000000140007ce4 f   libucrt:fgets.obj
 0001:000074f8       ??$parse_command_line@_W@@YAXPEA_WPEAPEA_W0PEA_K2@Z 00000001400084f8 f   libucrt:argv_parsing.obj
 0001:00007880       ??$common_initialize_environment_nolock@_W@@YAHXZ 0000000140008880 f   libucrt:environment_initialization.obj
 0001:000078e8       ??$create_environment@_W@@YAQEAPEA_WQEA_W@Z 00000001400088e8 f   libucrt:environment_initialization.obj
 0001:000079fc       ??$free_environment@D@@YAXQEAPEAD@Z 00000001400089fc f   libucrt:environment_initialization.obj
 0001:000079fc       ??$free_environment@_W@@YAXQEAPEA_W@Z 00000001400089fc f   libucrt:environment_initialization.obj
 0001:00007a40       ??$uninitialize_environment_internal@D@@YAXAEAPEAPEAD@Z 0000000140008a40 f   libucrt:environment_initialization.obj
 0001:00007a5c       ??$uninitialize_environment_internal@_W@@YAXAEAPEAPEA_W@Z 0000000140008a5c f   libucrt:environment_initialization.obj
 0001:00007bb0       ??$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z 0000000140008bb0 f   libucrt:exit.obj
 0001:00007be8       ??R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ 0000000140008be8 f   libucrt:exit.obj
 0001:00007cac       ?atexit_exception_filter@@YAHK@Z 0000000140008cac f   libucrt:exit.obj
 0001:00007cb8       ?common_exit@@YAXHW4_crt_exit_cleanup_mode@@W4_crt_exit_return_mode@@@Z 0000000140008cb8 f   libucrt:exit.obj
 0001:00007d74       ?exit_or_terminate_process@@YAXI@Z 0000000140008d74 f   libucrt:exit.obj
 0001:00007dc0       ?try_cor_exit_process@@YAXI@Z 0000000140008dc0 f   libucrt:exit.obj
 0001:00007fe8       ??$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z 0000000140008fe8 f   libucrt:wsetlocale.obj
 0001:00008150       ??$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z 0000000140009150 f   libucrt:onexit.obj
 0001:0000818c       ??$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z 000000014000918c f   libucrt:onexit.obj
 0001:000081c8       ??R<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@QEBAHXZ 00000001400091c8 f   libucrt:onexit.obj
 0001:00008378       ??R<lambda_f03950bc5685219e0bcd2087efbe011e>@@QEBAHXZ 0000000140009378 f   libucrt:onexit.obj
 0001:0000854c       initialize_global_variables 000000014000954c f   libucrt:initialization.obj
 0001:00008560       initialize_c               0000000140009560 f   libucrt:initialization.obj
 0001:00008584       uninitialize_environment   0000000140009584 f   libucrt:initialization.obj
 0001:00008594       initialize_pointers        0000000140009594 f   libucrt:initialization.obj
 0001:000085d4       uninitialize_vcruntime     00000001400095d4 f   libucrt:initialization.obj
 0001:000085dc       uninitialize_allocated_memory 00000001400095dc f   libucrt:initialization.obj
 0001:0000861c       uninitialize_allocated_io_buffers 000000014000961c f   libucrt:initialization.obj
 0001:000087b0       $$000000                   00000001400097b0     libucrt:strncmp.obj
 0001:00008b20       ?find_or_allocate_unused_stream_nolock@@YA?AV__crt_stdio_stream@@XZ 0000000140009b20 f   libucrt:stream.obj
 0001:00008fe8       ??$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z 0000000140009fe8 f   libucrt:close.obj
 0001:00009228       ??$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z 000000014000a228 f   libucrt:fflush.obj
 0001:000092c4       ??$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z 000000014000a2c4 f   libucrt:fflush.obj
 0001:000093a4       ?common_flush_all@@YAH_N@Z 000000014000a3a4 f   libucrt:fflush.obj
 0001:00009544       ??$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z 000000014000a544 f   libucrt:per_thread_data.obj
 0001:00009584       ??$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z 000000014000a584 f   libucrt:per_thread_data.obj
 0001:000095c4       ??$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z 000000014000a5c4 f   libucrt:per_thread_data.obj
 0001:0000960c       ??$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z 000000014000a60c f   libucrt:per_thread_data.obj
 0001:0000966c       ?construct_ptd_array@@YAXQEAU__acrt_ptd@@@Z 000000014000a66c f   libucrt:per_thread_data.obj
 0001:0000973c       ?destroy_fls@@YAXPEAX@Z    000000014000a73c f   libucrt:per_thread_data.obj
 0001:0000975c       ?destroy_ptd_array@@YAXQEAU__acrt_ptd@@@Z 000000014000a75c f   libucrt:per_thread_data.obj
 0001:00009854       ?replace_current_thread_locale_nolock@@YAXQEAU__acrt_ptd@@QEAU__crt_locale_data@@@Z 000000014000a854 f   libucrt:per_thread_data.obj
 0001:00009dc4       ?initialize_inherited_file_handles_nolock@@YAXXZ 000000014000adc4 f   libucrt:ioinit.obj
 0001:00009eb4       ?initialize_stdio_handles_nolock@@YAXXZ 000000014000aeb4 f   libucrt:ioinit.obj
 0001:0000a404       ?<lambda_invoker_cdecl>@<lambda_861af8918f661c876f88da8747958ced>@@CAHPEBX0@Z 000000014000b404 f   libucrt:argv_wildcards.obj
 0001:0000a418       ??$common_expand_argv_wildcards@_W@@YAHQEAPEA_WQEAPEAPEA_W@Z 000000014000b418 f   libucrt:argv_wildcards.obj
 0001:0000a7e4       ??$copy_and_add_argument_to_buffer@_W@@YAHQEB_W0_KAEAV?$argument_list@_W@?A0x5f5c8891@@@Z 000000014000b7e4 f   libucrt:argv_wildcards.obj
 0001:0000a978       ??$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z 000000014000b978 f   libucrt:mbctype.obj
 0001:0000ab34       ?getSystemCP@@YAHH@Z       000000014000bb34 f   libucrt:mbctype.obj
 0001:0000abb4       ?setSBCS@@YAXPEAU__crt_multibyte_data@@@Z 000000014000bbb4 f   libucrt:mbctype.obj
 0001:0000ac44       ?setSBUpLow@@YAXPEAU__crt_multibyte_data@@@Z 000000014000bc44 f   libucrt:mbctype.obj
 0001:0000ae28       ?setmbcp_internal@@YAHH_NQEAU__acrt_ptd@@QEAPEAU__crt_multibyte_data@@@Z 000000014000be28 f   libucrt:mbctype.obj
 0001:0000afec       ?update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z 000000014000bfec f   libucrt:mbctype.obj
 0001:0000bc70       ?free_crt_array_internal@@YAXQEAPEBX_K@Z 000000014000cc70 f   libucrt:inittime.obj
 0001:0000c574       ?try_get_function@@YAPEAXW4function_id@?A0x391cf84c@@QEBDQEBW4module_id@2@2@Z 000000014000d574 f   libucrt:winapi_thunks.obj
 0001:0000cc4c       ??$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z 000000014000dc4c f   libucrt:signal.obj
 0001:0000d18c       ??$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z 000000014000e18c f   libucrt:open.obj
 0001:0000d250       ?configure_text_mode@@YAHHUfile_options@?A0xa9d50aae@@HAEAW4__crt_lowio_text_mode@@@Z 000000014000e250 f   libucrt:open.obj
 0001:0000d4e4       ?decode_options@@YA?AUfile_options@?A0xa9d50aae@@HHH@Z 000000014000e4e4 f   libucrt:open.obj
 0001:0000d6f0       ?truncate_ctrl_z_if_present@@YAHH@Z 000000014000e6f0 f   libucrt:open.obj
 0001:0000dbd0       ??$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z 000000014000ebd0 f   libucrt:commit.obj
 0001:0000dcf0       ?write_double_translated_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014000ecf0 f   libucrt:write.obj
 0001:0000e1c0       ?write_text_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014000f1c0 f   libucrt:write.obj
 0001:0000e2c4       ?write_text_utf16le_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014000f2c4 f   libucrt:write.obj
 0001:0000e3e0       ?write_text_utf8_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014000f3e0 f   libucrt:write.obj
 0001:0000eaa0       ??$common_refill_and_read_nolock@_W@@YAHV__crt_stdio_stream@@@Z 000000014000faa0 f   libucrt:_filbuf.obj
 0001:0000f1f0       ?__acrt_LCMapStringA_stat@@YAHPEAU__crt_locale_pointers@@PEB_WKPEBDHPEADHHH@Z 00000001400101f0 f   libucrt:lcmapstringa.obj
 0001:0000f5a0       ?initialize_multibyte@@YAHXZ 00000001400105a0 f   libucrt:multibyte_initializer.obj
 0001:0000faa0       ??$translate_text_mode_nolock@D@@YAHHQEAD_K@Z 0000000140010aa0 f   libucrt:read.obj
 0001:0000fc60       ??$translate_text_mode_nolock@_W@@YAHHQEA_W_K@Z 0000000140010c60 f   libucrt:read.obj
 0001:0000fedc       ?translate_ansi_or_utf8_nolock@@YAHHQEAD_KQEA_W1@Z 0000000140010edc f   libucrt:read.obj
 0001:000105ec       ??$common_lseek_nolock@_J@@YA_JH_JH@Z 00000001400115ec f   libucrt:lseek.obj
 0001:00010930       $$000000                   0000000140011930     libucrt:log10.obj
 0001:0001100c       _call_matherr              000000014001200c f   libucrt:libm_error.obj
 0001:00011074       _exception_enabled         0000000140012074 f   libucrt:libm_error.obj
 0001:000112f0       _log_special_common        00000001400122f0 f   libucrt:log_special.obj
 0001:00011390       $$000000                   0000000140012390     libucrt:fpsr.obj
 0001:00011980       $$000000                   0000000140012980     LIBCMT:chkstk.obj
 0001:000119f0       $$000000                   00000001400129f0     libvcruntime:memcmp.obj
 0001:00011b50       $$000000                   0000000140012b50     LIBCMT:guard_dispatch.obj
 0001:00011b70       ?dtor$0@?0??OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ@4HA 0000000140012b70 f   FileProtocolHandler.obj
 0001:00011b7c       ?dtor$1@?0??OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ@4HA 0000000140012b7c f   FileProtocolHandler.obj
 0001:00011b90       ?dtor$0@?0??GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ@4HA 0000000140012b90 f   FileProtocolHandler.obj
 0001:00011ba0       ?dtor$0@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012ba0 f   FileProtocolHandler.obj
 0001:00011bac       ?dtor$1@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bac f   FileProtocolHandler.obj
 0001:00011bb8       ?dtor$2@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bb8 f   FileProtocolHandler.obj
 0001:00011bc4       ?dtor$3@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bc4 f   FileProtocolHandler.obj
 0001:00011bd0       ?dtor$4@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bd0 f   FileProtocolHandler.obj
 0001:00011bdc       ?dtor$5@?0??Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bdc f   FileProtocolHandler.obj
 0001:00011bf0       ?dtor$0@?0??Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bf0 f   FileProtocolHandler.obj
 0001:00011bfc       ?dtor$1@?0??Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ@4HA 0000000140012bfc f   FileProtocolHandler.obj
 0001:00011c10       ?dtor$0@?0??HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z@4HA 0000000140012c10 f   FileProtocolHandler.obj
 0001:00011c20       ?dtor$0@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 0000000140012c20 f   FileProtocolHandler.obj
 0001:00011c2c       ?dtor$1@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 0000000140012c2c f   FileProtocolHandler.obj
 0001:00011c38       ?dtor$19@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 0000000140012c38 f   FileProtocolHandler.obj
 0001:00011c5e       ?dtor$3@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 0000000140012c5e f   FileProtocolHandler.obj
 0001:00011c6a       ?dtor$4@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 0000000140012c6a f   FileProtocolHandler.obj
 0001:00011c80       ?dtor$1@?0??OnInitDialog@@YAHPEAUHWND__@@0_J@Z@4HA 0000000140012c80 f   FileProtocolHandler.obj
 0001:00011c8c       ?dtor$2@?0??OnInitDialog@@YAHPEAUHWND__@@0_J@Z@4HA 0000000140012c8c f   FileProtocolHandler.obj
 0001:00011c98       ?dtor$4@?0??OnInitDialog@@YAHPEAUHWND__@@0_J@Z@4HA 0000000140012c98 f   FileProtocolHandler.obj
 0001:00011cb0       ?dtor$0@?0???$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z@4HA 0000000140012cb0 f   FileProtocolHandler.obj
 0001:00011cd6       ?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA 0000000140012cd6 f   LIBCMT:exe_wwinmain.obj
 0001:00011cf4       __scrt_is_nonwritable_in_current_image$filt$0 0000000140012cf4 f   LIBCMT:utility.obj
 0001:00011d0c       ?filt$0@?0???$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z@4HA 0000000140012d0c f   libvcruntime:risctrnsctrl.obj
 0001:00011d9d       __DestructExceptionObject$filt$0 0000000140012d9d f   libvcruntime:ehhelpers.obj
 0001:00011db5       ?filt$0@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 0000000140012db5 f   libvcruntime:frame.obj
 0001:00011dda       ?fin$1@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 0000000140012dda f   libvcruntime:frame.obj
 0001:00011e52       ?filt$0@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 0000000140012e52 f   libvcruntime:frame.obj
 0001:00011e68       ?fin$1@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 0000000140012e68 f   libvcruntime:frame.obj
 0001:00011e8b       ?fin$0@?0???$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z@4HA 0000000140012e8b f   libucrt:fopen.obj
 0001:00011eb6       fclose$fin$0               0000000140012eb6 f   libucrt:fclose.obj
 0001:00011ece       ?fin$0@?0???$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z@4HA 0000000140012ece f   libucrt:fgets.obj
 0001:00011ee6       _query_new_handler$fin$0   0000000140012ee6 f   libucrt:new_handler.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z@4HA 0000000140012efc f   libucrt:per_thread_data.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z@4HA 0000000140012efc f   libucrt:per_thread_data.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z@4HA 0000000140012efc f   libucrt:signal.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z@4HA 0000000140012efc f   libucrt:exit.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z@4HA 0000000140012efc f   libucrt:onexit.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z@4HA 0000000140012efc f   libucrt:per_thread_data.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z@4HA 0000000140012efc f   libucrt:mbctype.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z@4HA 0000000140012efc f   libucrt:onexit.obj
 0001:00011efc       ?fin$0@?0???$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z@4HA 0000000140012efc f   libucrt:per_thread_data.obj
 0001:00011f16       ?filt$0@?0???R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ@4HA 0000000140012f16 f   libucrt:exit.obj
 0001:00011f31       ?fin$0@?0???$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z@4HA 0000000140012f31 f   libucrt:wsetlocale.obj
 0001:00011f4b       _fcloseall$fin$0           0000000140012f4b f   libucrt:closeall.obj
 0001:00011f4b       ?fin$0@?0??__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ@4HA 0000000140012f4b f   libucrt:stream.obj
 0001:00011f64       ?fin$0@?0???$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z@4HA 0000000140012f64 f   libucrt:commit.obj
 0001:00011f64       ?fin$0@?0???$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z@4HA 0000000140012f64 f   libucrt:close.obj
 0001:00011f7e       ?fin$0@?0???$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z@4HA 0000000140012f7e f   libucrt:fflush.obj
 0001:00011f99       ?fin$0@?0???$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z@4HA 0000000140012f99 f   libucrt:fflush.obj
 0001:00011fb6       __acrt_initialize_lowio$fin$0 0000000140012fb6 f   libucrt:ioinit.obj
 0001:00011fb6       __acrt_lowio_ensure_fh_exists$fin$0 0000000140012fb6 f   libucrt:osfinfo.obj
 0001:00011fb6       _alloc_osfhnd$fin$0        0000000140012fb6 f   libucrt:osfinfo.obj
 0001:00011fcf       ?fin$0@?0??update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z@4HA 0000000140012fcf f   libucrt:mbctype.obj
 0001:00011fe8       __acrt_update_thread_locale_data$fin$0 0000000140012fe8 f   libucrt:locale_refcounting.obj
 0001:00012001       raise$fin$0                0000000140013001 f   libucrt:signal.obj
 0001:00012022       ?fin$0@?0???$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z@4HA 0000000140013022 f   libucrt:open.obj
 0001:00012075       _write$fin$0               0000000140013075 f   libucrt:write.obj
 0001:0001208c       ungetc$fin$0               000000014001308c f   libucrt:ungetc.obj
 0001:000120a4       _read$fin$0                00000001400130a4 f   libucrt:read.obj
 0001:000120bb       _ctrlfp$filt$0             00000001400130bb f   libucrt:fpctrl.obj
 0001:000120f0       _IsNonwritableInCurrentImage$filt$0 00000001400130f0 f   LIBCMT:pesect.obj
 0002:00000338       ?pre_cpp_initializer@@3P6AXXZEA 0000000140014338     LIBCMT:exe_wwinmain.obj
 0002:00000350       ?pre_c_initializer@@3P6AHXZEA 0000000140014350     LIBCMT:exe_wwinmain.obj
 0002:00000358       ?post_pgo_initializer@@3P6AHXZEA 0000000140014358     LIBCMT:exe_wwinmain.obj
 0002:00000448       GS_ExceptionPointers       0000000140014448     LIBCMT:gs_report.obj
 0002:000004a0       ?ExceptionTemplate@?1??UnwindNestedFrames@__FrameHandler3@@SAXPEA_KPEAUEHExceptionRecord@@PEAU_CONTEXT@@0PEAXPEBU_s_FuncInfo@@HHPEBU_s_HandlerType@@PEAU_xDISPATCHER_CONTEXT@@E@Z@4U_EXCEPTION_RECORD@@B 00000001400144a0     libvcruntime:risctrnsctrl.obj
 0002:00000540       ?ExceptionTemplate@?1??_CxxThrowException@@9@4UEHExceptionRecord@@B 0000000140014540     libvcruntime:throw.obj
 0002:000005a8       ?module_names@?A0x14c33c87@@3QBQEB_WB 00000001400145a8     libvcruntime:winapi_downlevel.obj
 0002:00000678       ?candidate_modules@?1??try_get_FlsAlloc@@YAP6AKP6AXPEAX@Z@ZXZ@4QBW4module_id@?A0x14c33c87@@B 0000000140014678     libvcruntime:winapi_downlevel.obj
 0002:00000690       ?candidate_modules@?1??try_get_FlsFree@@YAP6AHK@ZXZ@4QBW4module_id@?A0x14c33c87@@B 0000000140014690     libvcruntime:winapi_downlevel.obj
 0002:000006a0       ?candidate_modules@?1??try_get_FlsGetValue@@YAP6APEAXK@ZXZ@4QBW4module_id@?A0x14c33c87@@B 00000001400146a0     libvcruntime:winapi_downlevel.obj
 0002:000006b8       ?candidate_modules@?1??try_get_FlsSetValue@@YAP6AHKPEAX@ZXZ@4QBW4module_id@?A0x14c33c87@@B 00000001400146b8     libvcruntime:winapi_downlevel.obj
 0002:000006d0       ?candidate_modules@?1??try_get_InitializeCriticalSectionEx@@YAP6AHPEAU_RTL_CRITICAL_SECTION@@KK@ZXZ@4QBW4module_id@?A0x14c33c87@@B 00000001400146d0     libvcruntime:winapi_downlevel.obj
 0002:00000700       ?tokenTable@@3QBQEBDB      0000000140014700     libvcruntime:undname.obj
 0002:00000780       ?nameTable@@3QBQEBDB       0000000140014780     libvcruntime:undname.obj
 0002:00000a10       ?rttiTable@@3QBQEBDB       0000000140014a10     libvcruntime:undname.obj
 0002:000011d0       __acrt_initializers        00000001400151d0     libucrt:initialization.obj
 0002:000012d0       ?errtable@@3QBUerrentry@?A0x31fdb9ec@@B 00000001400152d0     libucrt:errno.obj
 0002:000022f8       ?_mb_locale_names@@3QBQEB_WB 00000001400162f8     libucrt:mbctype.obj
 0002:00002360       ?module_names@?A0x391cf84c@@3QBQEB_WB 0000000140016360     libucrt:winapi_thunks.obj
 0002:00002858       ?candidate_modules@?1??try_get_FlsAlloc@@YAP6AKP6AXPEAX@Z@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016858     libucrt:winapi_thunks.obj
 0002:00002860       ?candidate_modules@?1??try_get_FlsFree@@YAP6AHK@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016860     libucrt:winapi_thunks.obj
 0002:00002868       ?candidate_modules@?1??try_get_FlsGetValue@@YAP6APEAXK@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016868     libucrt:winapi_thunks.obj
 0002:00002870       ?candidate_modules@?1??try_get_FlsSetValue@@YAP6AHKPEAX@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016870     libucrt:winapi_thunks.obj
 0002:00002878       ?candidate_modules@?1??try_get_InitializeCriticalSectionEx@@YAP6AHPEAU_RTL_CRITICAL_SECTION@@KK@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016878     libucrt:winapi_thunks.obj
 0002:00002880       ?candidate_modules@?1??try_get_LCMapStringEx@@YAP6AHPEB_WK0HPEA_WHPEAU_nlsversioninfo@@PEAX_J@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016880     libucrt:winapi_thunks.obj
 0002:00002898       ?candidate_modules@?1??try_get_LocaleNameToLCID@@YAP6AKPEB_WK@ZXZ@4QBW4module_id@?A0x391cf84c@@B 0000000140016898     libucrt:winapi_thunks.obj
 0002:000028b4       ?candidate_modules@?1??try_get_AppPolicyGetProcessTerminationMethod@@YAP6AJPEAXPEAW4AppPolicyProcessTerminationMethod@@@ZXZ@4QBW4module_id@?A0x391cf84c@@B 00000001400168b4     libucrt:winapi_thunks.obj
 0002:000028e0       ?LcidToLocaleNameTable@?A0x881e4c05@@3QBULcidToLocaleName@1@B 00000001400168e0     libucrt:lcidtoname_downlevel.obj
 0002:00004340       ?LocaleNameToIndexTable@?A0x881e4c05@@3QBULocaleNameIndex@1@B 0000000140018340     libucrt:lcidtoname_downlevel.obj
 0002:00005be0       __real_ninf                0000000140019be0     libucrt:log10.obj
 0002:00005bf0       __real_inf                 0000000140019bf0     libucrt:log10.obj
 0002:00005c00       __real_neg_qnan            0000000140019c00     libucrt:log10.obj
 0002:00005c10       __real_qnanbit             0000000140019c10     libucrt:log10.obj
 0002:00005c20       __int_1023                 0000000140019c20     libucrt:log10.obj
 0002:00005c30       __mask_001                 0000000140019c30     libucrt:log10.obj
 0002:00005c40       __mask_mant                0000000140019c40     libucrt:log10.obj
 0002:00005c50       __mask_mant_top8           0000000140019c50     libucrt:log10.obj
 0002:00005c60       __mask_mant9               0000000140019c60     libucrt:log10.obj
 0002:00005c70       __real_log10_e             0000000140019c70     libucrt:log10.obj
 0002:00005c80       __real_log10_e_lead        0000000140019c80     libucrt:log10.obj
 0002:00005c90       __real_log10_e_tail        0000000140019c90     libucrt:log10.obj
 0002:00005ca0       __real_log10_2_lead        0000000140019ca0     libucrt:log10.obj
 0002:00005cb0       __real_log10_2_tail        0000000140019cb0     libucrt:log10.obj
 0002:00005cc0       __real_two                 0000000140019cc0     libucrt:log10.obj
 0002:00005cd0       __real_one                 0000000140019cd0     libucrt:log10.obj
 0002:00005ce0       __real_half                0000000140019ce0     libucrt:log10.obj
 0002:00005cf0       __mask_100                 0000000140019cf0     libucrt:log10.obj
 0002:00005d00       __real_1_over_512          0000000140019d00     libucrt:log10.obj
 0002:00005d10       __real_1_over_2            0000000140019d10     libucrt:log10.obj
 0002:00005d20       __real_1_over_3            0000000140019d20     libucrt:log10.obj
 0002:00005d30       __real_1_over_4            0000000140019d30     libucrt:log10.obj
 0002:00005d40       __real_1_over_5            0000000140019d40     libucrt:log10.obj
 0002:00005d50       __real_1_over_6            0000000140019d50     libucrt:log10.obj
 0002:00005d60       __real_neg_1023            0000000140019d60     libucrt:log10.obj
 0002:00005d70       __mask_2045                0000000140019d70     libucrt:log10.obj
 0002:00005d80       __real_threshold           0000000140019d80     libucrt:log10.obj
 0002:00005d90       __real_near_one_lt         0000000140019d90     libucrt:log10.obj
 0002:00005da0       __real_near_one_gt         0000000140019da0     libucrt:log10.obj
 0002:00005db0       __real_min_norm            0000000140019db0     libucrt:log10.obj
 0002:00005dc0       __real_notsign             0000000140019dc0     libucrt:log10.obj
 0002:00005dd0       __real_ca1                 0000000140019dd0     libucrt:log10.obj
 0002:00005de0       __real_ca2                 0000000140019de0     libucrt:log10.obj
 0002:00005df0       __real_ca3                 0000000140019df0     libucrt:log10.obj
 0002:00005e00       __real_ca4                 0000000140019e00     libucrt:log10.obj
 0002:00005e10       __mask_lower               0000000140019e10     libucrt:log10.obj
 0002:00005e20       __flag_x_zero              0000000140019e20     libucrt:log10.obj
 0002:00005e24       __flag_x_neg               0000000140019e24     libucrt:log10.obj
 0002:00005e28       __flag_x_nan               0000000140019e28     libucrt:log10.obj
 0002:00007680       __real@433fffffffffffff    000000014001b680     libucrt:fpsr.obj
 0002:00007688       __real@c33fffffffffffff    000000014001b688     libucrt:fpsr.obj
 0002:000078b0       $cppxdata$??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 000000014001b8b0     FileProtocolHandler.obj
 0002:000078d8       $cppxdata$?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 000000014001b8d8     FileProtocolHandler.obj
 0002:00007900       $cppxdata$?OnCommand@@YA_JPEAUHWND__@@H0I@Z 000000014001b900     FileProtocolHandler.obj
 0002:00007928       $cppxdata$?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 000000014001b928     FileProtocolHandler.obj
 0002:00007950       $cppxdata$?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 000000014001b950     FileProtocolHandler.obj
 0002:00007978       $cppxdata$??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 000000014001b978     FileProtocolHandler.obj
 0002:000079a0       $cppxdata$?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001b9a0     FileProtocolHandler.obj
 0002:000079c8       $cppxdata$?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001b9c8     FileProtocolHandler.obj
 0002:000079f0       $cppxdata$?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 000000014001b9f0     FileProtocolHandler.obj
 0002:00007a18       $cppxdata$?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 000000014001ba18     FileProtocolHandler.obj
 0002:000082b0       $unwind$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 000000014001c2b0     FileProtocolHandler.obj
 0002:000082c8       $chain$1$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 000000014001c2c8     FileProtocolHandler.obj
 0002:000082e0       $chain$2$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 000000014001c2e0     FileProtocolHandler.obj
 0002:000082f0       $unwind$?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 000000014001c2f0     FileProtocolHandler.obj
 0002:00008310       $stateUnwindMap$?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 000000014001c310     FileProtocolHandler.obj
 0002:00008328       $ip2state$?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 000000014001c328     FileProtocolHandler.obj
 0002:00008340       $unwind$?OpenFile@CFileProtocolHandlerService@?A0x9219411d@@QEAAJPEB_W@Z 000000014001c340     FileProtocolHandler.obj
 0002:0000835c       $unwind$_initterm_e        000000014001c35c     libucrt:initterm.obj
 0002:0000835c       $unwind$_RTC_Initialize    000000014001c35c     LIBCMT:initsect.obj
 0002:0000835c       $unwind$_ungetc_nolock     000000014001c35c     libucrt:ungetc.obj
 0002:0000835c       $unwind$?replace_current_thread_locale_nolock@@YAXQEAU__acrt_ptd@@QEAU__crt_locale_data@@@Z 000000014001c35c     libucrt:per_thread_data.obj
 0002:0000835c       $unwind$_updatetlocinfoEx_nolock 000000014001c35c     libucrt:locale_refcounting.obj
 0002:0000835c       $unwind$_RTC_Terminate     000000014001c35c     LIBCMT:initsect.obj
 0002:0000835c       $unwind$__acrt_execute_uninitializers 000000014001c35c     libucrt:shared_initialization.obj
 0002:0000835c       $unwind$_realloc_base      000000014001c35c     libucrt:realloc_base.obj
 0002:0000835c       $unwind$_fclose_nolock     000000014001c35c     libucrt:fclose.obj
 0002:0000835c       $unwind$__acrt_uninitialize_lowio 000000014001c35c     libucrt:ioinit.obj
 0002:0000835c       $unwind$_FindAndUnlinkFrame 000000014001c35c     libvcruntime:risctrnsctrl.obj
 0002:0000835c       $unwind$??_Gbad_alloc@std@@UEAAPEAXI@Z 000000014001c35c     libcpmt:xthrow.obj
 0002:0000835c       $unwind$__vcrt_FlsSetValue 000000014001c35c     libvcruntime:winapi_downlevel.obj
 0002:0000835c       $unwind$??$common_initialize_environment_nolock@_W@@YAHXZ 000000014001c35c     libucrt:environment_initialization.obj
 0002:0000835c       $unwind$__acrt_stdio_allocate_buffer_nolock 000000014001c35c     libucrt:_getbuf.obj
 0002:0000835c       $unwind$??_Glength_error@std@@UEAAPEAXI@Z 000000014001c35c     libcpmt:xthrow.obj
 0002:0000835c       $unwind$__acrt_errno_map_os_error 000000014001c35c     libucrt:errno.obj
 0002:0000835c       $unwind$??_Gexception@std@@UEAAPEAXI@Z 000000014001c35c     libcpmt:xthrow.obj
 0002:0000835c       $unwind$wcsncpy_s          000000014001c35c     libucrt:wcsncpy_s.obj
 0002:0000835c       $unwind$__acrt_FlsSetValue 000000014001c35c     libucrt:winapi_thunks.obj
 0002:0000835c       $unwind$_wfopen_s          000000014001c35c     libucrt:fopen.obj
 0002:0000835c       $unwind$??_Gbad_exception@std@@UEAAPEAXI@Z 000000014001c35c     libvcruntime:frame.obj
 0002:0000835c       $unwind$??_Glogic_error@std@@UEAAPEAXI@Z 000000014001c35c     libcpmt:xthrow.obj
 0002:0000835c       $unwind$?SetUnwindTryBlock@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 000000014001c35c     libvcruntime:ehstate.obj
 0002:0000835c       $unwind$??_Gbad_array_new_length@std@@UEAAPEAXI@Z 000000014001c35c     LIBCMT:throw_bad_alloc.obj
 0002:0000835c       $unwind$?<lambda_invoker_cdecl>@<lambda_1350e090c1767e0d7e74fd51cceb431d>@@CAHPEAUHWND__@@_J@Z 000000014001c35c     FileProtocolHandler.obj
 0002:0000835c       $unwind$__acrt_LocaleNameToLCID 000000014001c35c     libucrt:winapi_thunks.obj
 0002:0000835c       $unwind$_close_nolock      000000014001c35c     libucrt:close.obj
 0002:00008368       $unwind$?ProtocolName@CFileProtocolHandlerService@?A0x9219411d@@QEBA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 000000014001c368     FileProtocolHandler.obj
 0002:0000837c       $unwind$?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 000000014001c37c     FileProtocolHandler.obj
 0002:00008394       $stateUnwindMap$?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 000000014001c394     FileProtocolHandler.obj
 0002:000083a8       $ip2state$?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 000000014001c3a8     FileProtocolHandler.obj
 0002:000083c8       $unwind$?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c3c8     FileProtocolHandler.obj
 0002:000083f0       $stateUnwindMap$?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c3f0     FileProtocolHandler.obj
 0002:00008430       $ip2state$?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c430     FileProtocolHandler.obj
 0002:00008470       $unwind$?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c470     FileProtocolHandler.obj
 0002:00008490       $stateUnwindMap$?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c490     FileProtocolHandler.obj
 0002:000084a0       $ip2state$?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014001c4a0     FileProtocolHandler.obj
 0002:000084b8       $unwind$??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 000000014001c4b8     FileProtocolHandler.obj
 0002:000084c8       $stateUnwindMap$??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 000000014001c4c8     FileProtocolHandler.obj
 0002:000084c8       $stateUnwindMap$?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 000000014001c4c8     FileProtocolHandler.obj
 0002:000084d0       $ip2state$??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 000000014001c4d0     FileProtocolHandler.obj
 0002:000084d8       $unwind$??2@YAPEAX_K@Z     000000014001c4d8     LIBCMT:new_scalar.obj
 0002:000084d8       $unwind$_fflush_nolock     000000014001c4d8     libucrt:fflush.obj
 0002:000084d8       $unwind$_callnewh          000000014001c4d8     libucrt:new_handler.obj
 0002:000084d8       $unwind$__acrt_stdio_free_buffer_nolock 000000014001c4d8     libucrt:_freebuf.obj
 0002:000084d8       $unwind$??_Gtype_info@@UEAAPEAXI@Z 000000014001c4d8     LIBCMT:std_type_info_static.obj
 0002:000084d8       $unwind$?pre_c_initialization@@YAHXZ 000000014001c4d8     LIBCMT:exe_wwinmain.obj
 0002:000084d8       $unwind$??1?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@QEAA@XZ 000000014001c4d8     FileProtocolHandler.obj
 0002:000084d8       $unwind$?try_cor_exit_process@@YAXI@Z 000000014001c4d8     libucrt:exit.obj
 0002:000084d8       $unwind$??0bad_array_new_length@std@@QEAA@AEBV01@@Z 000000014001c4d8     LIBCMT:throw_bad_alloc.obj
 0002:000084d8       $unwind$?ExecutionInCatch@__FrameHandler3@@SA_NPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014001c4d8     libvcruntime:risctrnsctrl.obj
 0002:000084d8       $unwind$__acrt_AppPolicyGetProcessTerminationMethodInternal 000000014001c4d8     libucrt:winapi_thunks.obj
 0002:000084d8       $unwind$_set_statfp        000000014001c4d8     libucrt:fpctrl.obj
 0002:000084d8       $unwind$__raise_securityfailure 000000014001c4d8     LIBCMT:gs_report.obj
 0002:000084d8       $unwind$__acrt_get_process_end_policy 000000014001c4d8     libucrt:win_policies.obj
 0002:000084d8       $unwind$__acrt_getptd_head 000000014001c4d8     libucrt:per_thread_data.obj
 0002:000084d8       $unwind$?GetUnwindTryBlock@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014001c4d8     libvcruntime:ehstate.obj
 0002:000084d8       $unwind$??0bad_exception@std@@QEAA@AEBV01@@Z 000000014001c4d8     libvcruntime:frame.obj
 0002:000084d8       $unwind$??0exception@std@@QEAA@AEBV01@@Z 000000014001c4d8     libcpmt:xthrow.obj
 0002:000084d8       $unwind$?StateFromIp@__FrameHandler3@@SAHPEBU_s_FuncInfo@@PEAU_xDISPATCHER_CONTEXT@@_K@Z 000000014001c4d8     libvcruntime:ehstate.obj
 0002:000084d8       $unwind$?ExFilterRethrow@@YAHPEAU_EXCEPTION_POINTERS@@PEAUEHExceptionRecord@@PEAH@Z 000000014001c4d8     libvcruntime:frame.obj
 0002:000084d8       $unwind$_configthreadlocale 000000014001c4d8     libucrt:wsetlocale.obj
 0002:000084d8       $unwind$??0logic_error@std@@QEAA@AEBV01@@Z 000000014001c4d8     libcpmt:xthrow.obj
 0002:000084d8       $unwind$__acrt_update_locale_info 000000014001c4d8     libucrt:locale_update.obj
 0002:000084d8       $unwind$__acrt_uninitialize_stdio 000000014001c4d8     libucrt:_file.obj
 0002:000084d8       $unwind$__acrt_update_multibyte_info 000000014001c4d8     libucrt:locale_update.obj
 0002:000084d8       $unwind$__acrt_FlsGetValue 000000014001c4d8     libucrt:winapi_thunks.obj
 0002:000084d8       $unwind$__acrt_FlsFree     000000014001c4d8     libucrt:winapi_thunks.obj
 0002:000084d8       $unwind$_IsExceptionObjectToBeDestroyed 000000014001c4d8     libvcruntime:ehhelpers.obj
 0002:000084d8       $unwind$__std_exception_destroy 000000014001c4d8     libvcruntime:std_exception.obj
 0002:000084d8       $unwind$?exit_or_terminate_process@@YAXI@Z 000000014001c4d8     libucrt:exit.obj
 0002:000084d8       $unwind$__acrt_FlsAlloc    000000014001c4d8     libucrt:winapi_thunks.obj
 0002:000084d8       $unwind$_clrfp             000000014001c4d8     libucrt:fpctrl.obj
 0002:000084d8       $unwind$_SetImageBase      000000014001c4d8     libvcruntime:risctrnsctrl.obj
 0002:000084d8       $unwind$??0bad_alloc@std@@QEAA@AEBV01@@Z 000000014001c4d8     libcpmt:xthrow.obj
 0002:000084d8       $unwind$_calloc_base       000000014001c4d8     libucrt:calloc_base.obj
 0002:000084d8       $unwind$__acrt_uninitialize_winapi_thunks 000000014001c4d8     libucrt:winapi_thunks.obj
 0002:000084d8       $unwind$__vcrt_initialize_locks 000000014001c4d8     libvcruntime:locks.obj
 0002:000084d8       $unwind$??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ 000000014001c4d8     FileProtocolHandler.obj
 0002:000084d8       $unwind$__vcrt_uninitialize_locks 000000014001c4d8     libvcruntime:locks.obj
 0002:000084d8       $unwind$__acrt_allocate_buffer_for_argv 000000014001c4d8     libucrt:argv_parsing.obj
 0002:000084d8       $unwind$_onexit            000000014001c4d8     LIBCMT:utility.obj
 0002:000084d8       $unwind$__vcrt_FlsAlloc    000000014001c4d8     libvcruntime:winapi_downlevel.obj
 0002:000084d8       $unwind$__vcrt_FlsFree     000000014001c4d8     libvcruntime:winapi_downlevel.obj
 0002:000084d8       $unwind$__vcrt_FlsGetValue 000000014001c4d8     libvcruntime:winapi_downlevel.obj
 0002:000084d8       $unwind$_SetThrowImageBase 000000014001c4d8     libvcruntime:risctrnsctrl.obj
 0002:000084d8       $unwind$strcpy_s           000000014001c4d8     libucrt:strcpy_s.obj
 0002:000084d8       $unwind$??0length_error@std@@QEAA@AEBV01@@Z 000000014001c4d8     libcpmt:xthrow.obj
 0002:000084d8       $unwind$__acrt_initialize_locks 000000014001c4d8     libucrt:locks.obj
 0002:000084d8       $unwind$_CreateFrameInfo   000000014001c4d8     libvcruntime:risctrnsctrl.obj
 0002:000084d8       $unwind$wcscpy_s           000000014001c4d8     libucrt:wcscpy_s.obj
 0002:000084d8       $unwind$__acrt_uninitialize_locks 000000014001c4d8     libucrt:locks.obj
 0002:000084d8       $unwind$__scrt_uninitialize_crt 000000014001c4d8     LIBCMT:utility.obj
 0002:000084d8       $unwind$uninitialize_allocated_memory 000000014001c4d8     libucrt:initialization.obj
 0002:000084d8       $unwind$__scrt_initialize_crt 000000014001c4d8     LIBCMT:utility.obj
 0002:000084d8       $unwind$initialize_pointers 000000014001c4d8     libucrt:initialization.obj
 0002:000084d8       $unwind$__scrt_release_startup_lock 000000014001c4d8     LIBCMT:utility.obj
 0002:000084d8       $unwind$_malloc_base       000000014001c4d8     libucrt:malloc_base.obj
 0002:000084e0       $unwind$?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 000000014001c4e0     FileProtocolHandler.obj
 0002:00008500       $stateUnwindMap$?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 000000014001c500     FileProtocolHandler.obj
 0002:00008508       $ip2state$?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 000000014001c508     FileProtocolHandler.obj
 0002:00008520       $unwind$wWinMain           000000014001c520     FileProtocolHandler.obj
 0002:00008538       $chain$1$wWinMain          000000014001c538     FileProtocolHandler.obj
 0002:00008550       $chain$3$wWinMain          000000014001c550     FileProtocolHandler.obj
 0002:00008550       $chain$5$wWinMain          000000014001c550     FileProtocolHandler.obj
 0002:00008568       $chain$4$wWinMain          000000014001c568     FileProtocolHandler.obj
 0002:00008578       $unwind$?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 000000014001c578     FileProtocolHandler.obj
 0002:00008598       $ip2state$?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 000000014001c598     FileProtocolHandler.obj
 0002:000085b0       $unwind$?OnCommand@@YA_JPEAUHWND__@@H0I@Z 000000014001c5b0     FileProtocolHandler.obj
 0002:000085cc       $stateUnwindMap$?OnCommand@@YA_JPEAUHWND__@@H0I@Z 000000014001c5cc     FileProtocolHandler.obj
 0002:00008600       $ip2state$?OnCommand@@YA_JPEAUHWND__@@H0I@Z 000000014001c600     FileProtocolHandler.obj
 0002:00008658       $unwind$_ctrlfp$filt$0     000000014001c658     libucrt:fpctrl.obj
 0002:00008658       $unwind$_alloc_osfhnd$fin$0 000000014001c658     libucrt:osfinfo.obj
 0002:00008658       $unwind$?dtor$0@?0???$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z@4HA 000000014001c658     FileProtocolHandler.obj
 0002:00008658       $unwind$_read$fin$0        000000014001c658     libucrt:read.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z@4HA 000000014001c658     libucrt:per_thread_data.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z@4HA 000000014001c658     libucrt:exit.obj
 0002:00008658       $unwind$?fin$0@?0???$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z@4HA 000000014001c658     libucrt:fopen.obj
 0002:00008658       $unwind$?filt$0@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 000000014001c658     libvcruntime:frame.obj
 0002:00008658       $unwind$?fin$0@?0??__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ@4HA 000000014001c658     libucrt:stream.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z@4HA 000000014001c658     libucrt:per_thread_data.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z@4HA 000000014001c658     libucrt:wsetlocale.obj
 0002:00008658       $unwind$ungetc$fin$0       000000014001c658     libucrt:ungetc.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z@4HA 000000014001c658     libucrt:per_thread_data.obj
 0002:00008658       $unwind$?fin$1@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 000000014001c658     libvcruntime:frame.obj
 0002:00008658       $unwind$__acrt_update_thread_locale_data$fin$0 000000014001c658     libucrt:locale_refcounting.obj
 0002:00008658       $unwind$_fcloseall$fin$0   000000014001c658     libucrt:closeall.obj
 0002:00008658       $unwind$fclose$fin$0       000000014001c658     libucrt:fclose.obj
 0002:00008658       $unwind$__acrt_initialize_lowio$fin$0 000000014001c658     libucrt:ioinit.obj
 0002:00008658       $unwind$?filt$0@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 000000014001c658     libvcruntime:frame.obj
 0002:00008658       $unwind$?filt$0@?0???R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ@4HA 000000014001c658     libucrt:exit.obj
 0002:00008658       $unwind$?dtor$19@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 000000014001c658     FileProtocolHandler.obj
 0002:00008658       $unwind$__acrt_lowio_ensure_fh_exists$fin$0 000000014001c658     libucrt:osfinfo.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z@4HA 000000014001c658     libucrt:mbctype.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z@4HA 000000014001c658     libucrt:fflush.obj
 0002:00008658       $unwind$?fin$0@?0???$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z@4HA 000000014001c658     libucrt:fgets.obj
 0002:00008658       $unwind$_write$fin$0       000000014001c658     libucrt:write.obj
 0002:00008658       $unwind$__DestructExceptionObject$filt$0 000000014001c658     libvcruntime:ehhelpers.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z@4HA 000000014001c658     libucrt:signal.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z@4HA 000000014001c658     libucrt:fflush.obj
 0002:00008658       $unwind$?fin$0@?0??update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z@4HA 000000014001c658     libucrt:mbctype.obj
 0002:00008658       $unwind$_query_new_handler$fin$0 000000014001c658     libucrt:new_handler.obj
 0002:00008658       $unwind$raise$fin$0        000000014001c658     libucrt:signal.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z@4HA 000000014001c658     libucrt:commit.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z@4HA 000000014001c658     libucrt:onexit.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z@4HA 000000014001c658     libucrt:per_thread_data.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z@4HA 000000014001c658     libucrt:onexit.obj
 0002:00008658       $unwind$?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA 000000014001c658     LIBCMT:exe_wwinmain.obj
 0002:00008658       $unwind$?fin$0@?0???$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z@4HA 000000014001c658     libucrt:close.obj
 0002:00008658       $unwind$_IsNonwritableInCurrentImage$filt$0 000000014001c658     LIBCMT:pesect.obj
 0002:00008660       $unwind$?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 000000014001c660     FileProtocolHandler.obj
 0002:00008684       $stateUnwindMap$?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 000000014001c684     FileProtocolHandler.obj
 0002:000086b0       $ip2state$?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 000000014001c6b0     FileProtocolHandler.obj
 0002:00008700       $unwind$__acrt_initialize_multibyte 000000014001c700     libucrt:mbctype.obj
 0002:00008700       $unwind$_invoke_watson     000000014001c700     libucrt:invalid_parameter.obj
 0002:00008700       $unwind$__acrt_initialize_heap 000000014001c700     libucrt:heap_handle.obj
 0002:00008700       $unwind$__acrt_update_thread_multibyte_data 000000014001c700     libucrt:mbctype.obj
 0002:00008700       $unwind$_wcsnicmp          000000014001c700     libucrt:wcsnicmp.obj
 0002:00008700       $unwind$wWinMainCRTStartup 000000014001c700     LIBCMT:exe_wwinmain.obj
 0002:00008700       $unwind$?pre_cpp_initialization@@YAXXZ 000000014001c700     LIBCMT:exe_wwinmain.obj
 0002:00008700       $unwind$__report_rangecheckfailure 000000014001c700     LIBCMT:gs_report.obj
 0002:00008700       $unwind$?post_pgo_initialization@@YAHXZ 000000014001c700     LIBCMT:exe_wwinmain.obj
 0002:00008700       $unwind$_isatty            000000014001c700     libucrt:isatty.obj
 0002:00008700       $unwind$__acrt_uninitialize_ptd 000000014001c700     libucrt:per_thread_data.obj
 0002:00008700       $unwind$_msize_base        000000014001c700     libucrt:msize.obj
 0002:00008700       $unwind$__acrt_initialize_command_line 000000014001c700     libucrt:argv_data.obj
 0002:00008700       $unwind$__GSHandlerCheck   000000014001c700     LIBCMT:gshandler.obj
 0002:00008700       $unwind$__scrt_is_managed_app 000000014001c700     LIBCMT:utility_desktop.obj
 0002:00008700       $unwind$__std_terminate    000000014001c700     libvcruntime:ehhelpers.obj
 0002:00008700       $unwind$_set_new_mode      000000014001c700     libucrt:new_mode.obj
 0002:00008700       $unwind$?initialize_multibyte@@YAHXZ 000000014001c700     libucrt:multibyte_initializer.obj
 0002:00008700       $unwind$_fgetc_nolock      000000014001c700     libucrt:fgetc.obj
 0002:00008700       $unwind$__acrt_initialize_ptd 000000014001c700     libucrt:per_thread_data.obj
 0002:00008700       $unwind$_statfp            000000014001c700     libucrt:fpctrl.obj
 0002:00008700       $unwind$?GetCurrentState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014001c700     libvcruntime:ehstate.obj
 0002:00008700       $unwind$__doserrno         000000014001c700     libucrt:errno.obj
 0002:00008700       $unwind$_get_osfhandle     000000014001c700     libucrt:osfinfo.obj
 0002:00008700       $unwind$__vcrt_freefls     000000014001c700     libvcruntime:per_thread_data.obj
 0002:00008700       $unwind$_fileno            000000014001c700     libucrt:fileno.obj
 0002:00008700       $unwind$_errno             000000014001c700     libucrt:errno.obj
 0002:00008700       $unwind$__scrt_unhandled_exception_filter 000000014001c700     LIBCMT:utility_desktop.obj
 0002:00008700       $unwind$__vcrt_getptd      000000014001c700     libvcruntime:per_thread_data.obj
 0002:00008700       $unwind$__dcrt_uninitialize_environments_nolock 000000014001c700     libucrt:environment_initialization.obj
 0002:00008700       $unwind$__vcrt_uninitialize_ptd 000000014001c700     libvcruntime:per_thread_data.obj
 0002:00008700       $unwind$__vcrt_initialize_ptd 000000014001c700     libvcruntime:per_thread_data.obj
 0002:00008700       $unwind$_GetImageBase      000000014001c700     libvcruntime:risctrnsctrl.obj
 0002:00008700       $unwind$??$uninitialize_environment_internal@D@@YAXAEAPEAPEAD@Z 000000014001c700     libucrt:environment_initialization.obj
 0002:00008700       $unwind$_GetThrowImageBase 000000014001c700     libvcruntime:risctrnsctrl.obj
 0002:00008700       $unwind$??$uninitialize_environment_internal@_W@@YAXAEAPEAPEA_W@Z 000000014001c700     libucrt:environment_initialization.obj
 0002:00008700       $unwind$?_Xlen@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@SAXXZ 000000014001c700     FileProtocolHandler.obj
 0002:00008700       $unwind$_set_errno_from_matherr 000000014001c700     libucrt:fpexcept.obj
 0002:00008700       $unwind$_get_fmode         000000014001c700     libucrt:setmode.obj
 0002:00008700       $unwind$_set_fmode         000000014001c700     libucrt:setmode.obj
 0002:00008700       $unwind$__vcrt_uninitialize 000000014001c700     libvcruntime:initialization.obj
 0002:00008700       $unwind$atexit             000000014001c700     LIBCMT:utility.obj
 0002:00008700       $unwind$abort              000000014001c700     libucrt:abort.obj
 0002:00008700       $unwind$__pctype_func      000000014001c700     libucrt:ctype.obj
 0002:00008700       $unwind$uninitialize_allocated_io_buffers 000000014001c700     libucrt:initialization.obj
 0002:00008700       $unwind$__vcrt_initialize  000000014001c700     libvcruntime:initialization.obj
 0002:00008700       $unwind$__dcrt_terminate_console_output 000000014001c700     libucrt:initcon.obj
 0002:00008700       $unwind$__acrt_uninitialize 000000014001c700     libucrt:initialization.obj
 0002:00008700       $unwind$_register_thread_local_exe_atexit_callback 000000014001c700     libucrt:exit.obj
 0002:00008700       $unwind$initialize_c       000000014001c700     libucrt:initialization.obj
 0002:00008700       $unwind$__acrt_release_locale_ref 000000014001c700     libucrt:locale_refcounting.obj
 0002:00008700       $unwind$__scrt_initialize_default_local_stdio_options 000000014001c700     LIBCMT:default_local_stdio_options.obj
 0002:00008700       $unwind$uninitialize_environment 000000014001c700     libucrt:initialization.obj
 0002:00008700       $unwind$DialogProc         000000014001c700     FileProtocolHandler.obj
 0002:00008700       $unwind$__FrameUnwindFilter 000000014001c700     libvcruntime:ehhelpers.obj
 0002:00008700       $unwind$__scrt_acquire_startup_lock 000000014001c700     LIBCMT:utility.obj
 0002:00008708       $unwind$?__mbrtowc_utf8@__crt_mbstring@@YA_KPEA_WPEBD_KPEAU_Mbstatet@@@Z 000000014001c708     libucrt:mbrtowc.obj
 0002:00008708       $unwind$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 000000014001c708     FileProtocolHandler.obj
 0002:00008708       $unwind$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 000000014001c708     FileProtocolHandler.obj
 0002:00008708       $unwind$??0length_error@std@@QEAA@PEBD@Z 000000014001c708     libcpmt:xthrow.obj
 0002:00008710       $chain$1$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 000000014001c710     FileProtocolHandler.obj
 0002:00008728       $chain$2$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 000000014001c728     FileProtocolHandler.obj
 0002:00008738       $unwind$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 000000014001c738     FileProtocolHandler.obj
 0002:00008744       $chain$1$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 000000014001c744     FileProtocolHandler.obj
 0002:0000875c       $chain$2$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 000000014001c75c     FileProtocolHandler.obj
 0002:0000876c       $unwind$??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 000000014001c76c     FileProtocolHandler.obj
 0002:00008784       $stateUnwindMap$??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 000000014001c784     FileProtocolHandler.obj
 0002:00008790       $ip2state$??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 000000014001c790     FileProtocolHandler.obj
 0002:00008798       $unwind$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 000000014001c798     FileProtocolHandler.obj
 0002:000087a4       $chain$2$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 000000014001c7a4     FileProtocolHandler.obj
 0002:000087c0       $chain$4$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 000000014001c7c0     FileProtocolHandler.obj
 0002:000087dc       $chain$5$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 000000014001c7dc     FileProtocolHandler.obj
 0002:000087ec       $unwind$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 000000014001c7ec     FileProtocolHandler.obj
 0002:000087fc       $chain$2$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 000000014001c7fc     FileProtocolHandler.obj
 0002:00008818       $chain$3$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 000000014001c818     FileProtocolHandler.obj
 0002:00008828       $chain$4$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 000000014001c828     FileProtocolHandler.obj
 0002:00008844       $unwind$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 000000014001c844     FileProtocolHandler.obj
 0002:00008854       $chain$3$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 000000014001c854     FileProtocolHandler.obj
 0002:00008874       $chain$5$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 000000014001c874     FileProtocolHandler.obj
 0002:00008894       $chain$6$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 000000014001c894     FileProtocolHandler.obj
 0002:000088a4       $chain$1$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 000000014001c8a4     FileProtocolHandler.obj
 0002:000088bc       $chain$2$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 000000014001c8bc     FileProtocolHandler.obj
 0002:000088cc       $unwind$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 000000014001c8cc     FileProtocolHandler.obj
 0002:000088d8       $chain$2$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 000000014001c8d8     FileProtocolHandler.obj
 0002:000088f4       $chain$3$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 000000014001c8f4     FileProtocolHandler.obj
 0002:00008904       $unwind$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 000000014001c904     FileProtocolHandler.obj
 0002:00008910       $chain$2$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 000000014001c910     FileProtocolHandler.obj
 0002:0000892c       $chain$4$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 000000014001c92c     FileProtocolHandler.obj
 0002:00008948       $chain$5$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 000000014001c948     FileProtocolHandler.obj
 0002:00008958       $unwind$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 000000014001c958     FileProtocolHandler.obj
 0002:00008968       $chain$2$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 000000014001c968     FileProtocolHandler.obj
 0002:00008984       $chain$4$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 000000014001c984     FileProtocolHandler.obj
 0002:000089a0       $chain$5$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 000000014001c9a0     FileProtocolHandler.obj
 0002:000089b0       $unwind$_raise_exc         000000014001c9b0     libucrt:fpexcept.obj
 0002:000089b0       $unwind$?__scrt_throw_std_bad_alloc@@YAXXZ 000000014001c9b0     LIBCMT:throw_bad_alloc.obj
 0002:000089b0       $unwind$?_Xlength_error@std@@YAXPEBD@Z 000000014001c9b0     libcpmt:xthrow.obj
 0002:000089b0       $unwind$?__scrt_throw_std_bad_array_new_length@@YAXXZ 000000014001c9b0     LIBCMT:throw_bad_alloc.obj
 0002:000089b8       $xdatasym                  000000014001c9b8     LIBCMT:amdsecgs.obj
 0002:000089bc       $unwind$__report_securityfailure 000000014001c9bc     LIBCMT:gs_report.obj
 0002:000089c4       $unwind$__report_gsfailure 000000014001c9c4     LIBCMT:gs_report.obj
 0002:000089cc       $unwind$capture_current_context 000000014001c9cc     LIBCMT:gs_report.obj
 0002:000089d8       $unwind$capture_previous_context 000000014001c9d8     LIBCMT:gs_report.obj
 0002:000089e4       $unwind$?__scrt_common_main_seh@@YAHXZ 000000014001c9e4     LIBCMT:exe_wwinmain.obj
 0002:00008a18       $unwind$__scrt_is_nonwritable_in_current_image 000000014001ca18     LIBCMT:utility.obj
 0002:00008a38       $unwind$__scrt_is_nonwritable_in_current_image$filt$0 000000014001ca38     LIBCMT:utility.obj
 0002:00008a40       $unwind$_isleadbyte_l      000000014001ca40     libucrt:_wctype.obj
 0002:00008a40       $unwind$__dcrt_lowio_ensure_console_output_initialized 000000014001ca40     libucrt:initcon.obj
 0002:00008a40       $unwind$?getSystemCP@@YAHH@Z 000000014001ca40     libucrt:mbctype.obj
 0002:00008a40       $unwind$__scrt_initialize_onexit_tables 000000014001ca40     LIBCMT:utility.obj
 0002:00008a48       $unwind$__security_init_cookie 000000014001ca48     LIBCMT:gs_support.obj
 0002:00008a54       $unwind$__scrt_get_show_window_mode 000000014001ca54     LIBCMT:utility_desktop.obj
 0002:00008a5c       $unwind$__scrt_fastfail    000000014001ca5c     LIBCMT:utility_desktop.obj
 0002:00008a6c       $unwind$__isa_available_init 000000014001ca6c     LIBCMT:cpu_disp.obj
 0002:00008a80       $xdatasym                  000000014001ca80     LIBCMT:guard_dispatch.obj
 0002:00008a84       $unwind$__acrt_InitializeCriticalSectionEx 000000014001ca84     libucrt:winapi_thunks.obj
 0002:00008a84       $unwind$__acrt_getptd      000000014001ca84     libucrt:per_thread_data.obj
 0002:00008a84       $unwind$?free_crt_array_internal@@YAXQEAPEBX_K@Z 000000014001ca84     libucrt:inittime.obj
 0002:00008a84       $unwind$__acrt_execute_initializers 000000014001ca84     libucrt:shared_initialization.obj
 0002:00008a84       $unwind$??$common_lseek_nolock@_J@@YA_JH_JH@Z 000000014001ca84     libucrt:lseek.obj
 0002:00008a84       $unwind$??0_LocaleUpdate@@QEAA@QEAU__crt_locale_pointers@@@Z 000000014001ca84     libucrt:_wctype.obj
 0002:00008a84       $unwind$?CatchTryBlock@__FrameHandler3@@SAPEBU_s_TryBlockMapEntry@@PEBU_s_FuncInfo@@H@Z 000000014001ca84     libvcruntime:risctrnsctrl.obj
 0002:00008a84       $unwind$__vcrt_getptd_noexit 000000014001ca84     libvcruntime:per_thread_data.obj
 0002:00008a84       $unwind$_exception_enabled 000000014001ca84     libucrt:libm_error.obj
 0002:00008a84       $unwind$__acrt_stdio_flush_nolock 000000014001ca84     libucrt:fflush.obj
 0002:00008a84       $unwind$__vcrt_InitializeCriticalSectionEx 000000014001ca84     libvcruntime:winapi_downlevel.obj
 0002:00008a84       $unwind$?FrameUnwindToEmptyState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014001ca84     libvcruntime:risctrnsctrl.obj
 0002:00008a84       $unwind$__acrt_getptd_noexit 000000014001ca84     libucrt:per_thread_data.obj
 0002:00008a94       $unwind$?GetEstablisherFrame@__FrameHandler3@@SAPEA_KPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@0@Z 000000014001ca94     libvcruntime:risctrnsctrl.obj
 0002:00008aac       $unwind$?UnwindNestedFrames@__FrameHandler3@@SAXPEA_KPEAUEHExceptionRecord@@PEAU_CONTEXT@@0PEAXPEBU_s_FuncInfo@@HHPEBU_s_HandlerType@@PEAU_xDISPATCHER_CONTEXT@@E@Z 000000014001caac     libvcruntime:risctrnsctrl.obj
 0002:00008ac0       $unwind$?GetRangeOfTrysToCheck@__FrameHandler3@@SA?AU?$pair@Viterator@TryBlockMap@__FrameHandler3@@V123@@std@@AEAVTryBlockMap@1@HH@Z 000000014001cac0     libvcruntime:risctrnsctrl.obj
 0002:00008ad8       $unwind$__CxxFrameHandler3 000000014001cad8     libvcruntime:risctrnsctrl.obj
 0002:00008ae8       $unwind$??$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z 000000014001cae8     libvcruntime:risctrnsctrl.obj
 0002:00008b08       $unwind$?filt$0@?0???$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z@4HA 000000014001cb08     libvcruntime:risctrnsctrl.obj
 0002:00008b14       $unwind$__DestructExceptionObject 000000014001cb14     libvcruntime:ehhelpers.obj
 0002:00008b34       $unwind$__acrt_stdio_refill_and_read_narrow_nolock 000000014001cb34     libucrt:_filbuf.obj
 0002:00008b34       $unwind$_free_osfhnd       000000014001cb34     libucrt:osfinfo.obj
 0002:00008b34       $unwind$__std_exception_copy 000000014001cb34     libvcruntime:std_exception.obj
 0002:00008b48       $unwind$_CxxThrowException 000000014001cb48     libvcruntime:throw.obj
 0002:00008b58       $unwind$__C_specific_handler 000000014001cb58     libvcruntime:riscchandler.obj
 0002:00008b78       $xdatasym                  000000014001cb78     libvcruntime:memset.obj
 0002:00008b88       $unwind$?FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 000000014001cb88     libvcruntime:frame.obj
 0002:00008bd4       $unwind$?find_or_allocate_unused_stream_nolock@@YA?AV__crt_stdio_stream@@XZ 000000014001cbd4     libucrt:stream.obj
 0002:00008bd4       $unwind$__acrt_lowio_create_handle_array 000000014001cbd4     libucrt:osfinfo.obj
 0002:00008bd4       $unwind$__acrt_free_locale 000000014001cbd4     libucrt:locale_refcounting.obj
 0002:00008bd4       $unwind$_seh_filter_exe    000000014001cbd4     libucrt:exception_filter.obj
 0002:00008bd4       $unwind$?GetHandlerSearchState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014001cbd4     libvcruntime:frame.obj
 0002:00008bd4       $unwind$_recalloc_base     000000014001cbd4     libucrt:recalloc.obj
 0002:00008bd4       $unwind$?Is_bad_exception_allowed@@YAEPEBU_s_ESTypeList@@@Z 000000014001cbd4     libvcruntime:frame.obj
 0002:00008bd4       $unwind$__dcrt_get_wide_environment_from_os 000000014001cbd4     libucrt:get_environment_from_os.obj
 0002:00008bd4       $unwind$?setSBCS@@YAXPEAU__crt_multibyte_data@@@Z 000000014001cbd4     libucrt:mbctype.obj
 0002:00008bd4       $unwind$_initterm          000000014001cbd4     libucrt:initterm.obj
 0002:00008be8       $unwind$?CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z 000000014001cbe8     libvcruntime:frame.obj
 0002:00008c24       $unwind$?fin$1@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 000000014001cc24     libvcruntime:frame.obj
 0002:00008c30       $unwind$?try_get_function@@YAPEAXW4function_id@?A0x391cf84c@@QEBDQEBW4module_id@2@2@Z 000000014001cc30     libucrt:winapi_thunks.obj
 0002:00008c30       $unwind$?try_get_function@@YAPEAXW4function_id@?A0x14c33c87@@QEBDQEBW4module_id@2@2@Z 000000014001cc30     libvcruntime:winapi_downlevel.obj
 0002:00008c30       $unwind$?IsInExceptionSpec@@YAEPEAUEHExceptionRecord@@PEBU_s_ESTypeList@@@Z 000000014001cc30     libvcruntime:frame.obj
 0002:00008c4c       $unwind$??$__InternalCxxFrameHandler@V__FrameHandler3@@@@YA?AW4_EXCEPTION_DISPOSITION@@PEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H1E@Z 000000014001cc4c     libvcruntime:frame.obj
 0002:00008c64       $unwind$__acrt_lowio_set_os_handle 000000014001cc64     libucrt:osfinfo.obj
 0002:00008c64       $unwind$??$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z 000000014001cc64     libucrt:openfile.obj
 0002:00008c64       $unwind$?initialize_stdio_handles_nolock@@YAXXZ 000000014001cc64     libucrt:ioinit.obj
 0002:00008c64       $unwind$__GSHandlerCheck_EH 000000014001cc64     LIBCMT:gshandlereh.obj
 0002:00008c64       $unwind$??$TypeMatchHelper@V__FrameHandler3@@@@YAHPEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_ThrowInfo@@@Z 000000014001cc64     libvcruntime:frame.obj
 0002:00008c64       $unwind$__acrt_initialize_stdio 000000014001cc64     libucrt:_file.obj
 0002:00008c64       $unwind$??$common_refill_and_read_nolock@_W@@YAHV__crt_stdio_stream@@@Z 000000014001cc64     libucrt:_filbuf.obj
 0002:00008c7c       $unwind$??$BuildCatchObjectHelperInternal@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 000000014001cc7c     libvcruntime:frame.obj
 0002:00008cbc       $unwind$??$BuildCatchObjectInternal@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 000000014001ccbc     libvcruntime:frame.obj
 0002:00008ce8       $unwind$??$FindHandler@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@EH1@Z 000000014001cce8     libvcruntime:frame.obj
 0002:00008d04       $unwind$??$CatchIt@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@PEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_TryBlockMapEntry@@H1EE@Z 000000014001cd04     libvcruntime:frame.obj
 0002:00008d1c       $unwind$??$FindHandlerForForeignException@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@HH1@Z 000000014001cd1c     libvcruntime:frame.obj
 0002:00008d38       $xdatasym                  000000014001cd38     libvcruntime:notify.obj
 0002:00008d44       $unwind$__vcrt_initialize_winapi_thunks 000000014001cd44     libvcruntime:winapi_downlevel.obj
 0002:00008d44       $unwind$__acrt_initialize_winapi_thunks 000000014001cd44     libucrt:winapi_thunks.obj
 0002:00008d4c       $unwind$__vcrt_uninitialize_winapi_thunks 000000014001cd4c     libvcruntime:winapi_downlevel.obj
 0002:00008d58       $xdatasym                  000000014001cd58     libvcruntime:handlers.obj
 0002:00008d68       $xdatasym                  000000014001cd68     libvcruntime:memcpy.obj
 0002:00008d78       $unwind$??$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z 000000014001cd78     libucrt:fopen.obj
 0002:00008da4       $unwind$fclose             000000014001cda4     libucrt:fclose.obj
 0002:00008dc8       $unwind$??$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z 000000014001cdc8     libucrt:fgets.obj
 0002:00008df4       $unwind$_wcsnicmp_l        000000014001cdf4     libucrt:wcsnicmp.obj
 0002:00008e10       $unwind$_log10_special     000000014001ce10     libucrt:log_special.obj
 0002:00008e10       $unwind$_wsopen_s          000000014001ce10     libucrt:open.obj
 0002:00008e10       $unwind$_invalid_parameter_noinfo 000000014001ce10     libucrt:invalid_parameter.obj
 0002:00008e10       $unwind$_invalid_parameter_noinfo_noreturn 000000014001ce10     libucrt:invalid_parameter.obj
 0002:00008e18       $unwind$__acrt_call_reportfault 000000014001ce18     libucrt:invalid_parameter.obj
 0002:00008e38       $unwind$_invalid_parameter 000000014001ce38     libucrt:invalid_parameter.obj
 0002:00008e4c       $unwind$_query_new_handler 000000014001ce4c     libucrt:new_handler.obj
 0002:00008e6c       $unwind$_configure_wide_argv 000000014001ce6c     libucrt:argv_parsing.obj
 0002:00008e80       $unwind$??$parse_command_line@_W@@YAXPEA_WPEAPEA_W0PEA_K2@Z 000000014001ce80     libucrt:argv_parsing.obj
 0002:00008e98       $unwind$??$free_environment@D@@YAXQEAPEAD@Z 000000014001ce98     libucrt:environment_initialization.obj
 0002:00008e98       $unwind$??$free_environment@_W@@YAXQEAPEA_W@Z 000000014001ce98     libucrt:environment_initialization.obj
 0002:00008ea4       $unwind$??$create_environment@_W@@YAQEAPEA_WQEA_W@Z 000000014001cea4     libucrt:environment_initialization.obj
 0002:00008ebc       $unwind$?common_exit@@YAXHW4_crt_exit_cleanup_mode@@W4_crt_exit_return_mode@@@Z 000000014001cebc     libucrt:exit.obj
 0002:00008ec8       $unwind$??R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ 000000014001cec8     libucrt:exit.obj
 0002:00008ee8       $unwind$??$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z 000000014001cee8     libucrt:exit.obj
 0002:00008f0c       $unwind$_setmode_nolock    000000014001cf0c     libucrt:setmode.obj
 0002:00008f1c       $unwind$__acrt_uninitialize_locale 000000014001cf1c     libucrt:wsetlocale.obj
 0002:00008f1c       $unwind$__acrt_get_sigabrt_handler 000000014001cf1c     libucrt:signal.obj
 0002:00008f24       $unwind$??$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z 000000014001cf24     libucrt:wsetlocale.obj
 0002:00008f4c       $unwind$_register_onexit_function 000000014001cf4c     libucrt:onexit.obj
 0002:00008f54       $unwind$_execute_onexit_table 000000014001cf54     libucrt:onexit.obj
 0002:00008f5c       $unwind$??R<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@QEBAHXZ 000000014001cf5c     libucrt:onexit.obj
 0002:00008f74       $unwind$__acrt_DownlevelLocaleNameToLCID 000000014001cf74     libucrt:lcidtoname_downlevel.obj
 0002:00008f74       $unwind$??R<lambda_f03950bc5685219e0bcd2087efbe011e>@@QEBAHXZ 000000014001cf74     libucrt:onexit.obj
 0002:00008f8c       $unwind$??$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z 000000014001cf8c     libucrt:onexit.obj
 0002:00008fb0       $unwind$??$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z 000000014001cfb0     libucrt:onexit.obj
 0002:00008fd4       $unwind$terminate          000000014001cfd4     libucrt:terminate.obj
 0002:00008ff8       $xdatasym                  000000014001cff8     libucrt:strncmp.obj
 0002:00008ffc       $unwind$?__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ 000000014001cffc     libucrt:stream.obj
 0002:0000901c       $unwind$_wopenfile         000000014001d01c     libucrt:openfile.obj
 0002:00009030       $unwind$_free_base         000000014001d030     libucrt:free_base.obj
 0002:00009030       $unwind$__acrt_locale_free_lc_time_if_unreferenced 000000014001d030     libucrt:locale_refcounting.obj
 0002:00009030       $unwind$__acrt_locale_free_numeric 000000014001d030     libucrt:initnum.obj
 0002:00009030       $unwind$?destroy_fls@@YAXPEAX@Z 000000014001d030     libucrt:per_thread_data.obj
 0002:00009038       $unwind$_commit            000000014001d038     libucrt:commit.obj
 0002:00009038       $unwind$_close             000000014001d038     libucrt:close.obj
 0002:00009040       $unwind$??$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z 000000014001d040     libucrt:close.obj
 0002:00009064       $unwind$?common_flush_all@@YAH_N@Z 000000014001d064     libucrt:fflush.obj
 0002:0000906c       $unwind$??$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z 000000014001d06c     libucrt:fflush.obj
 0002:00009090       $unwind$??$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z 000000014001d090     libucrt:fflush.obj
 0002:000090b8       $unwind$iswctype           000000014001d0b8     libucrt:iswctype.obj
 0002:000090c4       $unwind$?construct_ptd_array@@YAXQEAU__acrt_ptd@@@Z 000000014001d0c4     libucrt:per_thread_data.obj
 0002:000090cc       $unwind$?destroy_ptd_array@@YAXQEAU__acrt_ptd@@@Z 000000014001d0cc     libucrt:per_thread_data.obj
 0002:000090d4       $unwind$??$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z 000000014001d0d4     libucrt:per_thread_data.obj
 0002:000090f8       $unwind$??$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z 000000014001d0f8     libucrt:per_thread_data.obj
 0002:0000911c       $unwind$??$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z 000000014001d11c     libucrt:per_thread_data.obj
 0002:00009140       $unwind$??$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z 000000014001d140     libucrt:per_thread_data.obj
 0002:00009164       $unwind$_fgetwc_nolock     000000014001d164     libucrt:fgetwc.obj
 0002:00009174       $unwind$__acrt_initialize_lowio 000000014001d174     libucrt:ioinit.obj
 0002:00009194       $unwind$?initialize_inherited_file_handles_nolock@@YAXXZ 000000014001d194     libucrt:ioinit.obj
 0002:000091b0       $unwind$_towlower_l        000000014001d1b0     libucrt:towlower.obj
 0002:000091b8       $unwind$??$common_expand_argv_wildcards@_W@@YAHQEAPEA_WQEAPEAPEA_W@Z 000000014001d1b8     libucrt:argv_wildcards.obj
 0002:000091dc       $unwind$??$copy_and_add_argument_to_buffer@_W@@YAHQEB_W0_KAEAV?$argument_list@_W@?A0x5f5c8891@@@Z 000000014001d1dc     libucrt:argv_wildcards.obj
 0002:000091f8       $unwind$_setmbcp_nolock    000000014001d1f8     libucrt:mbctype.obj
 0002:00009218       $unwind$?update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z 000000014001d218     libucrt:mbctype.obj
 0002:00009240       $unwind$?setmbcp_internal@@YAHH_NQEAU__acrt_ptd@@QEAPEAU__crt_multibyte_data@@@Z 000000014001d240     libucrt:mbctype.obj
 0002:00009250       $unwind$?setSBUpLow@@YAXPEAU__crt_multibyte_data@@@Z 000000014001d250     libucrt:mbctype.obj
 0002:0000926c       $unwind$??$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z 000000014001d26c     libucrt:mbctype.obj
 0002:00009290       $unwind$__GSHandlerCheckCommon 000000014001d290     LIBCMT:gshandler.obj
 0002:00009290       $unwind$__acrt_WideCharToMultiByte 000000014001d290     libucrt:widechartomultibyte.obj
 0002:00009298       $unwind$_alloc_osfhnd      000000014001d298     libucrt:osfinfo.obj
 0002:000092c8       $unwind$__acrt_lowio_destroy_handle_array 000000014001d2c8     libucrt:osfinfo.obj
 0002:000092d8       $unwind$__acrt_lowio_ensure_fh_exists 000000014001d2d8     libucrt:osfinfo.obj
 0002:00009304       $unwind$__acrt_locale_free_monetary 000000014001d304     libucrt:initmon.obj
 0002:0000930c       $unwind$__acrt_locale_free_time 000000014001d30c     libucrt:inittime.obj
 0002:0000931c       $unwind$__acrt_GetStringTypeA 000000014001d31c     libucrt:getstringtypea.obj
 0002:00009344       $unwind$__acrt_update_thread_locale_data 000000014001d344     libucrt:locale_refcounting.obj
 0002:00009368       $unwind$__acrt_LCMapStringW 000000014001d368     libucrt:lcmapstringw.obj
 0002:00009368       $unwind$__acrt_LCMapStringEx 000000014001d368     libucrt:winapi_thunks.obj
 0002:00009368       $unwind$_mbtowc_l          000000014001d368     libucrt:mbtowc.obj
 0002:0000937c       $unwind$raise              000000014001d37c     libucrt:signal.obj
 0002:000093b8       $unwind$??$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z 000000014001d3b8     libucrt:signal.obj
 0002:000093dc       $unwind$_fcloseall         000000014001d3dc     libucrt:closeall.obj
 0002:00009400       $unwind$_wsopen_nolock     000000014001d400     libucrt:open.obj
 0002:00009420       $unwind$??$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z 000000014001d420     libucrt:open.obj
 0002:00009444       $unwind$?fin$0@?0???$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z@4HA 000000014001d444     libucrt:open.obj
 0002:0000944c       $unwind$?decode_options@@YA?AUfile_options@?A0xa9d50aae@@HHH@Z 000000014001d44c     libucrt:open.obj
 0002:00009460       $unwind$?truncate_ctrl_z_if_present@@YAHH@Z 000000014001d460     libucrt:open.obj
 0002:00009470       $unwind$?configure_text_mode@@YAHHUfile_options@?A0xa9d50aae@@HAEAW4__crt_lowio_text_mode@@@Z 000000014001d470     libucrt:open.obj
 0002:00009488       $unwind$??$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z 000000014001d488     libucrt:commit.obj
 0002:000094ac       $unwind$_write             000000014001d4ac     libucrt:write.obj
 0002:000094dc       $unwind$_write_nolock      000000014001d4dc     libucrt:write.obj
 0002:000094f4       $unwind$?write_double_translated_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014001d4f4     libucrt:write.obj
 0002:00009518       $unwind$?write_text_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014001d518     libucrt:write.obj
 0002:00009518       $unwind$?write_text_utf16le_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014001d518     libucrt:write.obj
 0002:00009538       $unwind$?write_text_utf8_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 000000014001d538     libucrt:write.obj
 0002:0000955c       $unwind$ungetc             000000014001d55c     libucrt:ungetc.obj
 0002:00009580       $unwind$qsort              000000014001d580     libucrt:qsort.obj
 0002:00009598       $chain$4$qsort             000000014001d598     libucrt:qsort.obj
 0002:000095bc       $chain$5$qsort             000000014001d5bc     libucrt:qsort.obj
 0002:000095cc       $unwind$__acrt_LCMapStringA 000000014001d5cc     libucrt:lcmapstringa.obj
 0002:000095dc       $unwind$?__acrt_LCMapStringA_stat@@YAHPEAU__crt_locale_pointers@@PEB_WKPEBDHPEADHHH@Z 000000014001d5dc     libucrt:lcmapstringa.obj
 0002:00009604       $unwind$?__mbsrtowcs_utf8@__crt_mbstring@@YA_KPEA_WPEAPEBD_KPEAU_Mbstatet@@@Z 000000014001d604     libucrt:mbrtowc.obj
 0002:0000961c       $unwind$_chsize_nolock     000000014001d61c     libucrt:chsize.obj
 0002:00009638       $unwind$_read              000000014001d638     libucrt:read.obj
 0002:00009668       $unwind$_read_nolock       000000014001d668     libucrt:read.obj
 0002:00009680       $unwind$?translate_ansi_or_utf8_nolock@@YAHHQEAD_KQEA_W1@Z 000000014001d680     libucrt:read.obj
 0002:0000969c       $unwind$??$translate_text_mode_nolock@D@@YAHHQEAD_K@Z 000000014001d69c     libucrt:read.obj
 0002:000096b4       $unwind$??$translate_text_mode_nolock@_W@@YAHHQEA_W_K@Z 000000014001d6b4     libucrt:read.obj
 0002:000096cc       $unwind$_putwch_nolock     000000014001d6cc     libucrt:putwch.obj
 0002:000096d4       $unwind$?__mbrtoc32_utf8@__crt_mbstring@@YA_KPEA_UPEBD_KPEAU_Mbstatet@@@Z 000000014001d6d4     libucrt:mbrtoc32.obj
 0002:000096f0       $xdatasym                  000000014001d6f0     libucrt:log10.obj
 0002:000096fc       $unwind$__dcrt_write_console 000000014001d6fc     libucrt:initcon.obj
 0002:00009710       $unwind$_call_matherr      000000014001d710     libucrt:libm_error.obj
 0002:00009718       $unwind$_handle_error      000000014001d718     libucrt:libm_error.obj
 0002:00009738       $unwind$__acrt_initialize_fma3 000000014001d738     libucrt:fma3_available.obj
 0002:00009740       $unwind$_log_special_common 000000014001d740     libucrt:log_special.obj
 0002:00009750       $xdatasym                  000000014001d750     libucrt:fpsr.obj
 0002:00009758       $unwind$_raise_exc_ex      000000014001d758     libucrt:fpexcept.obj
 0002:0000976c       $unwind$_ctrlfp            000000014001d76c     libucrt:fpctrl.obj
 0002:00009794       $unwind$_IsNonwritableInCurrentImage 000000014001d794     LIBCMT:pesect.obj
 0002:000097b8       $xdatasym                  000000014001d7b8     LIBCMT:chkstk.obj
 0002:000097c0       $xdatasym                  000000014001d7c0     libvcruntime:memcmp.obj
 0002:00009db8       .idata$6                   000000014001ddb8     kernel32:KERNEL32.dll
 0002:00009e9e       .idata$6                   000000014001de9e     user32:USER32.dll
 0002:00009efc       .idata$6                   000000014001defc     advapi32:ADVAPI32.dll
 0002:00009f1c       .idata$6                   000000014001df1c     shell32:SHELL32.dll
 0002:00009f62       .idata$6                   000000014001df62     shlwapi:SHLWAPI.dll
 0003:00000030       ?__vcrt_flsindex@@3KA      000000014001f030     libvcruntime:per_thread_data.obj
 0003:00000050       ?errno_no_memory@@3HA      000000014001f050     libucrt:errno.obj
 0003:00000054       ?doserrno_no_memory@@3KA   000000014001f054     libucrt:errno.obj
 0003:00000168       ?__acrt_flsindex@@3KA      000000014001f168     libucrt:per_thread_data.obj
 0003:00000560       _mbctypes                  000000014001f560     libucrt:mbctype.obj
 0003:00000670       _mbcasemaps                000000014001f670     libucrt:mbctype.obj
 0003:00000770       ?__rgctypeflag@@3PADA      000000014001f770     libucrt:mbctype.obj
 0003:00000780       ?__rgcode_page_info@@3PAUcode_page_info@@A 000000014001f780     libucrt:mbctype.obj
 0003:00000a20       ?__dcrt_lowio_console_output_handle@@3PEAXEA 000000014001fa20     libucrt:initcon.obj
 0003:00000a30       ?dazSupported@?1??_ctrlfp@@9@9 000000014001fa30     libucrt:fpctrl.obj
 0003:00000bf0       GS_ExceptionRecord         000000014001fbf0     LIBCMT:gs_report.obj
 0003:00000c90       GS_ContextRecord           000000014001fc90     LIBCMT:gs_report.obj
 0003:00001170       ?is_initialized_as_dll@@3_NA 0000000140020170     LIBCMT:utility.obj
 0003:00001171       ?module_local_atexit_table_initialized@@3_NA 0000000140020171     LIBCMT:utility.obj
 0003:00001178       ?module_local_atexit_table@@3U_onexit_table_t@@A 0000000140020178     LIBCMT:utility.obj
 0003:00001190       ?module_local_at_quick_exit_table@@3U_onexit_table_t@@A 0000000140020190     LIBCMT:utility.obj
 0003:000011e0       ?__vcrt_startup_thread_ptd@@3U__vcrt_ptd@@A 00000001400201e0     libvcruntime:per_thread_data.obj
 0003:00001270       __vcrt_lock_table          0000000140020270     libvcruntime:locks.obj
 0003:00001298       __vcrt_locks_initialized   0000000140020298     libvcruntime:locks.obj
 0003:000012a0       ?module_handles@@3PAPEAUHINSTANCE__@@A 00000001400202a0     libvcruntime:winapi_downlevel.obj
 0003:000012b8       ?encoded_function_pointers@@3PAPEAXA 00000001400202b8     libvcruntime:winapi_downlevel.obj
 0003:00001328       ?heap@@3V_HeapManager@@A   0000000140020328     libvcruntime:undname.obj
 0003:00001350       ?__acrt_invalid_parameter_handler@@3V?$dual_state_global@P6AXPEB_W00I_K@Z@__crt_state_management@@A 0000000140020350     libucrt:invalid_parameter.obj
 0003:00001358       ?__acrt_new_handler@@3V?$dual_state_global@P6AH_K@Z@__crt_state_management@@A 0000000140020358     libucrt:new_handler.obj
 0003:00001360       ?__acrt_app_type@@3W4_crt_app_type@@A 0000000140020360     libucrt:report_runtime_error.obj
 0003:00001368       ?user_matherr@@3V?$dual_state_global@P6AHPEAU_exception@@@Z@__crt_state_management@@A 0000000140020368     libucrt:matherr.obj
 0003:00001370       ?program_name@?1???$common_configure_argv@_W@@YAHW4_crt_argv_mode@@@Z@4PA_WA 0000000140020370     libucrt:argv_parsing.obj
 0003:000015a0       ?empty_string@?1???$common_wincmdln@_W@@YAPEA_WXZ@4PA_WA 00000001400205a0     libucrt:argv_winmain.obj
 0003:000015a4       ?c_termination_complete@@3JA 00000001400205a4     libucrt:exit.obj
 0003:000015a8       ?thread_local_exit_callback_func@@3P6AXPEAXK0@ZEA 00000001400205a8     libucrt:exit.obj
 0003:000015b8       ?__acrt_global_new_mode@@3V?$dual_state_global@J@__crt_state_management@@A 00000001400205b8     libucrt:new_mode.obj
 0003:00001a20       ?__acrt_lock_table@@3PAU_RTL_CRITICAL_SECTION@@A 0000000140020a20     libucrt:locks.obj
 0003:00001c50       ?__acrt_locks_initialized@@3IA 0000000140020c50     libucrt:locks.obj
 0003:00001c70       ?fSystemSet@@3HA           0000000140020c70     libucrt:mbctype.obj
 0003:00001c74       ?initialized@?1??__acrt_initialize_multibyte@@9@4_NA 0000000140020c74     libucrt:mbctype.obj
 0003:00001cb0       ?module_handles@@3PAPEAUHINSTANCE__@@A 0000000140020cb0     libucrt:winapi_thunks.obj
 0003:00001d50       ?encoded_function_pointers@@3PAPEAXA 0000000140020d50     libucrt:winapi_thunks.obj
 0003:00001e70       ?ctrlc_action@@3V?$dual_state_global@P6AXH@Z@__crt_state_management@@A 0000000140020e70     libucrt:signal.obj
 0003:00001e78       ?ctrlbreak_action@@3V?$dual_state_global@P6AXH@Z@__crt_state_management@@A 0000000140020e78     libucrt:signal.obj
 0003:00001e80       ?abort_action@@3V?$dual_state_global@P6AXH@Z@__crt_state_management@@A 0000000140020e80     libucrt:signal.obj
 0003:00001e88       ?term_action@@3V?$dual_state_global@P6AXH@Z@__crt_state_management@@A 0000000140020e88     libucrt:signal.obj
 0003:00001ea0       ?internal_state@?1??_mbtowc_l@@9@4U_Mbstatet@@A 0000000140020ea0     libucrt:mbtowc.obj
 0003:00001eb0       ?internal_pst@?1??__mbrtoc32_utf8@__crt_mbstring@@YA_KPEA_UPEBD_KPEAU_Mbstatet@@@Z@4U3@A 0000000140020eb0     libucrt:mbrtoc32.obj
 0003:00002068       ?s_app@@3PEAVCFileProtocolHandlerService@?A0x9219411d@@EA 0000000140021068     FileProtocolHandler.obj
 0004:00000000       $pdata$??0exception@std@@QEAA@AEBV01@@Z 0000000140022000     libcpmt:xthrow.obj
 0004:0000000c       $pdata$??_Gexception@std@@UEAAPEAXI@Z 000000014002200c     libcpmt:xthrow.obj
 0004:0000000c       $pdata$??_Gbad_array_new_length@std@@UEAAPEAXI@Z 000000014002200c     LIBCMT:throw_bad_alloc.obj
 0004:0000000c       $pdata$??_Gbad_alloc@std@@UEAAPEAXI@Z 000000014002200c     libcpmt:xthrow.obj
 0004:0000000c       $pdata$??_Glogic_error@std@@UEAAPEAXI@Z 000000014002200c     libcpmt:xthrow.obj
 0004:0000000c       $pdata$??_Gbad_exception@std@@UEAAPEAXI@Z 000000014002200c     libvcruntime:frame.obj
 0004:0000000c       $pdata$??_Glength_error@std@@UEAAPEAXI@Z 000000014002200c     libcpmt:xthrow.obj
 0004:00000018       $pdata$??0bad_alloc@std@@QEAA@AEBV01@@Z 0000000140022018     libcpmt:xthrow.obj
 0004:00000024       $pdata$?_Xlength_error@std@@YAXPEBD@Z 0000000140022024     libcpmt:xthrow.obj
 0004:00000030       $pdata$??0logic_error@std@@QEAA@AEBV01@@Z 0000000140022030     libcpmt:xthrow.obj
 0004:0000003c       $pdata$??0length_error@std@@QEAA@PEBD@Z 000000014002203c     libcpmt:xthrow.obj
 0004:00000048       $pdata$??0length_error@std@@QEAA@AEBV01@@Z 0000000140022048     libcpmt:xthrow.obj
 0004:00000060       $pdata$__report_securityfailure 0000000140022060     LIBCMT:gs_report.obj
 0004:0000006c       $pdata$__report_rangecheckfailure 000000014002206c     LIBCMT:gs_report.obj
 0004:00000078       $pdata$__report_gsfailure  0000000140022078     LIBCMT:gs_report.obj
 0004:00000084       $pdata$capture_current_context 0000000140022084     LIBCMT:gs_report.obj
 0004:00000090       $pdata$capture_previous_context 0000000140022090     LIBCMT:gs_report.obj
 0004:0000009c       $pdata$__raise_securityfailure 000000014002209c     LIBCMT:gs_report.obj
 0004:000000a8       $pdata$??2@YAPEAX_K@Z      00000001400220a8     LIBCMT:new_scalar.obj
 0004:000000b4       $pdata$?pre_c_initialization@@YAHXZ 00000001400220b4     LIBCMT:exe_wwinmain.obj
 0004:000000c0       $pdata$?post_pgo_initialization@@YAHXZ 00000001400220c0     LIBCMT:exe_wwinmain.obj
 0004:000000cc       $pdata$?pre_cpp_initialization@@YAXXZ 00000001400220cc     LIBCMT:exe_wwinmain.obj
 0004:000000d8       $pdata$?__scrt_common_main_seh@@YAHXZ 00000001400220d8     LIBCMT:exe_wwinmain.obj
 0004:000000e4       $pdata$?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA 00000001400220e4     LIBCMT:exe_wwinmain.obj
 0004:000000f0       $pdata$wWinMainCRTStartup  00000001400220f0     LIBCMT:exe_wwinmain.obj
 0004:000000fc       $pdata$??_Gtype_info@@UEAAPEAXI@Z 00000001400220fc     LIBCMT:std_type_info_static.obj
 0004:00000108       $pdata$??0bad_array_new_length@std@@QEAA@AEBV01@@Z 0000000140022108     LIBCMT:throw_bad_alloc.obj
 0004:00000114       $pdata$?__scrt_throw_std_bad_alloc@@YAXXZ 0000000140022114     LIBCMT:throw_bad_alloc.obj
 0004:00000120       $pdata$?__scrt_throw_std_bad_array_new_length@@YAXXZ 0000000140022120     LIBCMT:throw_bad_alloc.obj
 0004:0000012c       $pdata$atexit              000000014002212c     LIBCMT:utility.obj
 0004:00000138       $pdata$_onexit             0000000140022138     LIBCMT:utility.obj
 0004:00000144       $pdata$__scrt_is_nonwritable_in_current_image 0000000140022144     LIBCMT:utility.obj
 0004:00000150       $pdata$__scrt_is_nonwritable_in_current_image$filt$0 0000000140022150     LIBCMT:utility.obj
 0004:0000015c       $pdata$__scrt_acquire_startup_lock 000000014002215c     LIBCMT:utility.obj
 0004:00000168       $pdata$__scrt_release_startup_lock 0000000140022168     LIBCMT:utility.obj
 0004:00000174       $pdata$__scrt_initialize_crt 0000000140022174     LIBCMT:utility.obj
 0004:00000180       $pdata$__scrt_uninitialize_crt 0000000140022180     LIBCMT:utility.obj
 0004:0000018c       $pdata$__scrt_initialize_onexit_tables 000000014002218c     LIBCMT:utility.obj
 0004:00000198       $pdata$__security_init_cookie 0000000140022198     LIBCMT:gs_support.obj
 0004:000001a4       $pdata$__scrt_initialize_default_local_stdio_options 00000001400221a4     LIBCMT:default_local_stdio_options.obj
 0004:000001b0       $pdata$__scrt_get_show_window_mode 00000001400221b0     LIBCMT:utility_desktop.obj
 0004:000001bc       $pdata$__scrt_is_managed_app 00000001400221bc     LIBCMT:utility_desktop.obj
 0004:000001c8       $pdata$__scrt_fastfail     00000001400221c8     LIBCMT:utility_desktop.obj
 0004:000001d4       $pdata$__scrt_unhandled_exception_filter 00000001400221d4     LIBCMT:utility_desktop.obj
 0004:000001e0       $pdata$_RTC_Initialize     00000001400221e0     LIBCMT:initsect.obj
 0004:000001ec       $pdata$_RTC_Terminate      00000001400221ec     LIBCMT:initsect.obj
 0004:000001f8       $pdata$__isa_available_init 00000001400221f8     LIBCMT:cpu_disp.obj
 0004:00000210       $pdata$?CatchTryBlock@__FrameHandler3@@SAPEBU_s_TryBlockMapEntry@@PEBU_s_FuncInfo@@H@Z 0000000140022210     libvcruntime:risctrnsctrl.obj
 0004:0000021c       $pdata$?ExecutionInCatch@__FrameHandler3@@SA_NPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 000000014002221c     libvcruntime:risctrnsctrl.obj
 0004:00000228       $pdata$?FrameUnwindToEmptyState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 0000000140022228     libvcruntime:risctrnsctrl.obj
 0004:00000234       $pdata$?GetEstablisherFrame@__FrameHandler3@@SAPEA_KPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@0@Z 0000000140022234     libvcruntime:risctrnsctrl.obj
 0004:00000240       $pdata$?UnwindNestedFrames@__FrameHandler3@@SAXPEA_KPEAUEHExceptionRecord@@PEAU_CONTEXT@@0PEAXPEBU_s_FuncInfo@@HHPEBU_s_HandlerType@@PEAU_xDISPATCHER_CONTEXT@@E@Z 0000000140022240     libvcruntime:risctrnsctrl.obj
 0004:0000024c       $pdata$?GetRangeOfTrysToCheck@__FrameHandler3@@SA?AU?$pair@Viterator@TryBlockMap@__FrameHandler3@@V123@@std@@AEAVTryBlockMap@1@HH@Z 000000014002224c     libvcruntime:risctrnsctrl.obj
 0004:00000258       $pdata$_GetImageBase       0000000140022258     libvcruntime:risctrnsctrl.obj
 0004:00000264       $pdata$_SetImageBase       0000000140022264     libvcruntime:risctrnsctrl.obj
 0004:00000270       $pdata$_GetThrowImageBase  0000000140022270     libvcruntime:risctrnsctrl.obj
 0004:0000027c       $pdata$_SetThrowImageBase  000000014002227c     libvcruntime:risctrnsctrl.obj
 0004:00000288       $pdata$_CreateFrameInfo    0000000140022288     libvcruntime:risctrnsctrl.obj
 0004:00000294       $pdata$_FindAndUnlinkFrame 0000000140022294     libvcruntime:risctrnsctrl.obj
 0004:000002a0       $pdata$__CxxFrameHandler3  00000001400222a0     libvcruntime:risctrnsctrl.obj
 0004:000002ac       $pdata$??$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z 00000001400222ac     libvcruntime:risctrnsctrl.obj
 0004:000002b8       $pdata$?filt$0@?0???$_CallSETranslator@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@K1@Z@4HA 00000001400222b8     libvcruntime:risctrnsctrl.obj
 0004:000002c4       $pdata$__std_terminate     00000001400222c4     libvcruntime:ehhelpers.obj
 0004:000002d0       $pdata$_IsExceptionObjectToBeDestroyed 00000001400222d0     libvcruntime:ehhelpers.obj
 0004:000002dc       $pdata$__FrameUnwindFilter 00000001400222dc     libvcruntime:ehhelpers.obj
 0004:000002e8       $pdata$__DestructExceptionObject 00000001400222e8     libvcruntime:ehhelpers.obj
 0004:000002f4       $pdata$__DestructExceptionObject$filt$0 00000001400222f4     libvcruntime:ehhelpers.obj
 0004:00000300       $pdata$__std_exception_copy 0000000140022300     libvcruntime:std_exception.obj
 0004:0000030c       $pdata$__std_exception_destroy 000000014002230c     libvcruntime:std_exception.obj
 0004:00000318       $pdata$_CxxThrowException  0000000140022318     libvcruntime:throw.obj
 0004:00000324       $pdata$__C_specific_handler 0000000140022324     libvcruntime:riscchandler.obj
 0004:00000330       $pdata$__vcrt_initialize   0000000140022330     libvcruntime:initialization.obj
 0004:0000033c       $pdata$__vcrt_uninitialize 000000014002233c     libvcruntime:initialization.obj
 0004:00000360       $pdata$__vcrt_initialize_ptd 0000000140022360     libvcruntime:per_thread_data.obj
 0004:0000036c       $pdata$__vcrt_uninitialize_ptd 000000014002236c     libvcruntime:per_thread_data.obj
 0004:00000378       $pdata$__vcrt_getptd       0000000140022378     libvcruntime:per_thread_data.obj
 0004:00000384       $pdata$__vcrt_getptd_noexit 0000000140022384     libvcruntime:per_thread_data.obj
 0004:00000390       $pdata$__vcrt_freefls      0000000140022390     libvcruntime:per_thread_data.obj
 0004:0000039c       $pdata$?StateFromIp@__FrameHandler3@@SAHPEBU_s_FuncInfo@@PEAU_xDISPATCHER_CONTEXT@@_K@Z 000000014002239c     libvcruntime:ehstate.obj
 0004:000003a8       $pdata$?GetCurrentState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 00000001400223a8     libvcruntime:ehstate.obj
 0004:000003b4       $pdata$?SetUnwindTryBlock@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 00000001400223b4     libvcruntime:ehstate.obj
 0004:000003c0       $pdata$?GetUnwindTryBlock@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 00000001400223c0     libvcruntime:ehstate.obj
 0004:000003cc       $pdata$?FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z 00000001400223cc     libvcruntime:frame.obj
 0004:000003d8       $pdata$?filt$0@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 00000001400223d8     libvcruntime:frame.obj
 0004:000003e4       $pdata$?fin$1@?0??FrameUnwindToState@__FrameHandler3@@SAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z@4HA 00000001400223e4     libvcruntime:frame.obj
 0004:000003f0       $pdata$?GetHandlerSearchState@__FrameHandler3@@SAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z 00000001400223f0     libvcruntime:frame.obj
 0004:000003fc       $pdata$?CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z 00000001400223fc     libvcruntime:frame.obj
 0004:00000408       $pdata$?filt$0@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 0000000140022408     libvcruntime:frame.obj
 0004:00000414       $pdata$?fin$1@?0??CxxCallCatchBlock@__FrameHandler3@@SAPEAXPEAU_EXCEPTION_RECORD@@@Z@4HA 0000000140022414     libvcruntime:frame.obj
 0004:00000420       $pdata$??0bad_exception@std@@QEAA@AEBV01@@Z 0000000140022420     libvcruntime:frame.obj
 0004:0000042c       $pdata$?ExFilterRethrow@@YAHPEAU_EXCEPTION_POINTERS@@PEAUEHExceptionRecord@@PEAH@Z 000000014002242c     libvcruntime:frame.obj
 0004:00000438       $pdata$?IsInExceptionSpec@@YAEPEAUEHExceptionRecord@@PEBU_s_ESTypeList@@@Z 0000000140022438     libvcruntime:frame.obj
 0004:00000444       $pdata$?Is_bad_exception_allowed@@YAEPEBU_s_ESTypeList@@@Z 0000000140022444     libvcruntime:frame.obj
 0004:00000450       $pdata$??$__InternalCxxFrameHandler@V__FrameHandler3@@@@YA?AW4_EXCEPTION_DISPOSITION@@PEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H1E@Z 0000000140022450     libvcruntime:frame.obj
 0004:0000045c       $pdata$??$TypeMatchHelper@V__FrameHandler3@@@@YAHPEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_ThrowInfo@@@Z 000000014002245c     libvcruntime:frame.obj
 0004:00000468       $pdata$??$BuildCatchObjectHelperInternal@V__FrameHandler3@@@@YAHPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 0000000140022468     libvcruntime:frame.obj
 0004:00000474       $pdata$??$BuildCatchObjectInternal@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEAXPEBU_s_HandlerType@@PEBU_s_CatchableType@@@Z 0000000140022474     libvcruntime:frame.obj
 0004:00000480       $pdata$??$FindHandler@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@EH1@Z 0000000140022480     libvcruntime:frame.obj
 0004:0000048c       $pdata$??$CatchIt@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@PEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_TryBlockMapEntry@@H1EE@Z 000000014002248c     libvcruntime:frame.obj
 0004:00000498       $pdata$??$FindHandlerForForeignException@V__FrameHandler3@@@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@HH1@Z 0000000140022498     libvcruntime:frame.obj
 0004:000004c8       $pdata$__vcrt_initialize_locks 00000001400224c8     libvcruntime:locks.obj
 0004:000004d4       $pdata$__vcrt_uninitialize_locks 00000001400224d4     libvcruntime:locks.obj
 0004:000004e0       $pdata$__vcrt_FlsAlloc     00000001400224e0     libvcruntime:winapi_downlevel.obj
 0004:000004ec       $pdata$__vcrt_FlsFree      00000001400224ec     libvcruntime:winapi_downlevel.obj
 0004:000004f8       $pdata$__vcrt_FlsGetValue  00000001400224f8     libvcruntime:winapi_downlevel.obj
 0004:00000504       $pdata$__vcrt_FlsSetValue  0000000140022504     libvcruntime:winapi_downlevel.obj
 0004:00000510       $pdata$__vcrt_InitializeCriticalSectionEx 0000000140022510     libvcruntime:winapi_downlevel.obj
 0004:0000051c       $pdata$__vcrt_initialize_winapi_thunks 000000014002251c     libvcruntime:winapi_downlevel.obj
 0004:00000528       $pdata$__vcrt_uninitialize_winapi_thunks 0000000140022528     libvcruntime:winapi_downlevel.obj
 0004:00000534       $pdata$?try_get_function@@YAPEAXW4function_id@?A0x14c33c87@@QEBDQEBW4module_id@2@2@Z 0000000140022534     libvcruntime:winapi_downlevel.obj
 0004:00000570       $pdata$_wfopen_s           0000000140022570     libucrt:fopen.obj
 0004:0000057c       $pdata$??$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z 000000014002257c     libucrt:fopen.obj
 0004:00000588       $pdata$?fin$0@?0???$common_fsopen@_W@@YAPEAU_iobuf@@QEB_W0H@Z@4HA 0000000140022588     libucrt:fopen.obj
 0004:00000594       $pdata$fclose              0000000140022594     libucrt:fclose.obj
 0004:000005a0       $pdata$fclose$fin$0        00000001400225a0     libucrt:fclose.obj
 0004:000005ac       $pdata$_fclose_nolock      00000001400225ac     libucrt:fclose.obj
 0004:000005b8       $pdata$_isleadbyte_l       00000001400225b8     libucrt:_wctype.obj
 0004:000005c4       $pdata$??0_LocaleUpdate@@QEAA@QEAU__crt_locale_pointers@@@Z 00000001400225c4     libucrt:_wctype.obj
 0004:000005d0       $pdata$??$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z 00000001400225d0     libucrt:fgets.obj
 0004:000005dc       $pdata$?fin$0@?0???$common_fgets@_W@@YAPEA_WQEA_WHV__crt_stdio_stream@@@Z@4HA 00000001400225dc     libucrt:fgets.obj
 0004:000005e8       $pdata$_wcsnicmp           00000001400225e8     libucrt:wcsnicmp.obj
 0004:000005f4       $pdata$_wcsnicmp_l         00000001400225f4     libucrt:wcsnicmp.obj
 0004:00000600       $pdata$_invalid_parameter_noinfo 0000000140022600     libucrt:invalid_parameter.obj
 0004:0000060c       $pdata$_invalid_parameter_noinfo_noreturn 000000014002260c     libucrt:invalid_parameter.obj
 0004:00000618       $pdata$_invoke_watson      0000000140022618     libucrt:invalid_parameter.obj
 0004:00000624       $pdata$__acrt_call_reportfault 0000000140022624     libucrt:invalid_parameter.obj
 0004:00000630       $pdata$_invalid_parameter  0000000140022630     libucrt:invalid_parameter.obj
 0004:0000063c       $pdata$_callnewh           000000014002263c     libucrt:new_handler.obj
 0004:00000648       $pdata$_query_new_handler  0000000140022648     libucrt:new_handler.obj
 0004:00000654       $pdata$_query_new_handler$fin$0 0000000140022654     libucrt:new_handler.obj
 0004:00000660       $pdata$_seh_filter_exe     0000000140022660     libucrt:exception_filter.obj
 0004:0000066c       $pdata$_configure_wide_argv 000000014002266c     libucrt:argv_parsing.obj
 0004:00000678       $pdata$__acrt_allocate_buffer_for_argv 0000000140022678     libucrt:argv_parsing.obj
 0004:00000684       $pdata$??$parse_command_line@_W@@YAXPEA_WPEAPEA_W0PEA_K2@Z 0000000140022684     libucrt:argv_parsing.obj
 0004:00000690       $pdata$__dcrt_uninitialize_environments_nolock 0000000140022690     libucrt:environment_initialization.obj
 0004:0000069c       $pdata$??$common_initialize_environment_nolock@_W@@YAHXZ 000000014002269c     libucrt:environment_initialization.obj
 0004:000006a8       $pdata$??$uninitialize_environment_internal@D@@YAXAEAPEAPEAD@Z 00000001400226a8     libucrt:environment_initialization.obj
 0004:000006b4       $pdata$??$uninitialize_environment_internal@_W@@YAXAEAPEAPEA_W@Z 00000001400226b4     libucrt:environment_initialization.obj
 0004:000006c0       $pdata$??$free_environment@_W@@YAXQEAPEA_W@Z 00000001400226c0     libucrt:environment_initialization.obj
 0004:000006c0       $pdata$??$free_environment@D@@YAXQEAPEAD@Z 00000001400226c0     libucrt:environment_initialization.obj
 0004:000006cc       $pdata$??$create_environment@_W@@YAQEAPEA_WQEA_W@Z 00000001400226cc     libucrt:environment_initialization.obj
 0004:000006d8       $pdata$_initterm           00000001400226d8     libucrt:initterm.obj
 0004:000006e4       $pdata$_initterm_e         00000001400226e4     libucrt:initterm.obj
 0004:000006f0       $pdata$_register_thread_local_exe_atexit_callback 00000001400226f0     libucrt:exit.obj
 0004:000006fc       $pdata$?try_cor_exit_process@@YAXI@Z 00000001400226fc     libucrt:exit.obj
 0004:00000708       $pdata$?exit_or_terminate_process@@YAXI@Z 0000000140022708     libucrt:exit.obj
 0004:00000714       $pdata$?common_exit@@YAXHW4_crt_exit_cleanup_mode@@W4_crt_exit_return_mode@@@Z 0000000140022714     libucrt:exit.obj
 0004:00000720       $pdata$??R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ 0000000140022720     libucrt:exit.obj
 0004:0000072c       $pdata$?filt$0@?0???R<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@QEBA@XZ@4HA 000000014002272c     libucrt:exit.obj
 0004:00000738       $pdata$??$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z 0000000140022738     libucrt:exit.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z@4HA 0000000140022744     libucrt:per_thread_data.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@V<lambda_2358e3775559c9db80273638284d5e45>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_d80eeec6fff315bfe5c115232f3240e3>@@AEAV<lambda_6e4b09c48022b2350581041d5f6b0c4c>@@$$QEAV<lambda_2358e3775559c9db80273638284d5e45>@@@Z@4HA 0000000140022744     libucrt:exit.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z@4HA 0000000140022744     libucrt:per_thread_data.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z@4HA 0000000140022744     libucrt:per_thread_data.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z@4HA 0000000140022744     libucrt:onexit.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z@4HA 0000000140022744     libucrt:mbctype.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z@4HA 0000000140022744     libucrt:onexit.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z@4HA 0000000140022744     libucrt:per_thread_data.obj
 0004:00000744       $pdata$?fin$0@?0???$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z@4HA 0000000140022744     libucrt:signal.obj
 0004:00000750       $pdata$_set_fmode          0000000140022750     libucrt:setmode.obj
 0004:0000075c       $pdata$_get_fmode          000000014002275c     libucrt:setmode.obj
 0004:00000768       $pdata$_setmode_nolock     0000000140022768     libucrt:setmode.obj
 0004:00000774       $pdata$_configthreadlocale 0000000140022774     libucrt:wsetlocale.obj
 0004:00000780       $pdata$__acrt_uninitialize_locale 0000000140022780     libucrt:wsetlocale.obj
 0004:0000078c       $pdata$??$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z 000000014002278c     libucrt:wsetlocale.obj
 0004:00000798       $pdata$?fin$0@?0???$?RV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@V<lambda_38119f0e861e05405d8a144b9b982f0a>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_410d79af7f07d98d83a3f525b3859a53>@@AEAV<lambda_3e16ef9562a7dcce91392c22ab16ea36>@@$$QEAV<lambda_38119f0e861e05405d8a144b9b982f0a>@@@Z@4HA 0000000140022798     libucrt:wsetlocale.obj
 0004:000007a4       $pdata$_set_new_mode       00000001400227a4     libucrt:new_mode.obj
 0004:000007b0       $pdata$_register_onexit_function 00000001400227b0     libucrt:onexit.obj
 0004:000007bc       $pdata$_execute_onexit_table 00000001400227bc     libucrt:onexit.obj
 0004:000007c8       $pdata$??R<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@QEBAHXZ 00000001400227c8     libucrt:onexit.obj
 0004:000007d4       $pdata$??R<lambda_f03950bc5685219e0bcd2087efbe011e>@@QEBAHXZ 00000001400227d4     libucrt:onexit.obj
 0004:000007e0       $pdata$??$?RV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@V<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_638799b9deba96c50f710eeac98168cd>@@AEAV<lambda_22ebabd17bc4fa466a2aca6d8deb888d>@@$$QEAV<lambda_a6f7d7db0129f75315ebf26d50c089f1>@@@Z 00000001400227e0     libucrt:onexit.obj
 0004:000007ec       $pdata$??$?RV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@V<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_7777bce6b2f8c936911f934f8298dc43>@@AEAV<lambda_f03950bc5685219e0bcd2087efbe011e>@@$$QEAV<lambda_3883c3dff614d5e0c5f61bb1ac94921c>@@@Z 00000001400227ec     libucrt:onexit.obj
 0004:000007f8       $pdata$__acrt_uninitialize 00000001400227f8     libucrt:initialization.obj
 0004:00000804       $pdata$initialize_c        0000000140022804     libucrt:initialization.obj
 0004:00000810       $pdata$uninitialize_environment 0000000140022810     libucrt:initialization.obj
 0004:0000081c       $pdata$initialize_pointers 000000014002281c     libucrt:initialization.obj
 0004:00000828       $pdata$uninitialize_allocated_memory 0000000140022828     libucrt:initialization.obj
 0004:00000834       $pdata$uninitialize_allocated_io_buffers 0000000140022834     libucrt:initialization.obj
 0004:00000840       $pdata$terminate           0000000140022840     libucrt:terminate.obj
 0004:0000084c       $pdata$strcpy_s            000000014002284c     libucrt:strcpy_s.obj
 0004:00000858       $pdata$abort               0000000140022858     libucrt:abort.obj
 0004:00000870       $pdata$_errno              0000000140022870     libucrt:errno.obj
 0004:0000087c       $pdata$__doserrno          000000014002287c     libucrt:errno.obj
 0004:00000888       $pdata$__acrt_errno_map_os_error 0000000140022888     libucrt:errno.obj
 0004:00000894       $pdata$__acrt_initialize_stdio 0000000140022894     libucrt:_file.obj
 0004:000008a0       $pdata$__acrt_uninitialize_stdio 00000001400228a0     libucrt:_file.obj
 0004:000008ac       $pdata$?__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ 00000001400228ac     libucrt:stream.obj
 0004:000008b8       $pdata$_fcloseall$fin$0    00000001400228b8     libucrt:closeall.obj
 0004:000008b8       $pdata$?fin$0@?0??__acrt_stdio_allocate_stream@@YA?AV__crt_stdio_stream@@XZ@4HA 00000001400228b8     libucrt:stream.obj
 0004:000008c4       $pdata$?find_or_allocate_unused_stream_nolock@@YA?AV__crt_stdio_stream@@XZ 00000001400228c4     libucrt:stream.obj
 0004:000008d0       $pdata$_wopenfile          00000001400228d0     libucrt:openfile.obj
 0004:000008dc       $pdata$??$__acrt_stdio_parse_mode@_W@@YA?AU__acrt_stdio_stream_mode@@QEB_W@Z 00000001400228dc     libucrt:openfile.obj
 0004:000008e8       $pdata$_free_base          00000001400228e8     libucrt:free_base.obj
 0004:000008f4       $pdata$_close              00000001400228f4     libucrt:close.obj
 0004:00000900       $pdata$_close_nolock       0000000140022900     libucrt:close.obj
 0004:0000090c       $pdata$??$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z 000000014002290c     libucrt:close.obj
 0004:00000918       $pdata$?fin$0@?0???$?RV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@V<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_751a882b2c74d4b022dec766aa51a29a>@@AEAV<lambda_628dfdc04ba53c8bfc02c9951375f3f5>@@$$QEAV<lambda_f6c7be5f7998530c34de24c7437d6b54>@@@Z@4HA 0000000140022918     libucrt:close.obj
 0004:00000918       $pdata$?fin$0@?0???$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z@4HA 0000000140022918     libucrt:commit.obj
 0004:00000924       $pdata$_fileno             0000000140022924     libucrt:fileno.obj
 0004:00000930       $pdata$__acrt_stdio_free_buffer_nolock 0000000140022930     libucrt:_freebuf.obj
 0004:0000093c       $pdata$_fflush_nolock      000000014002293c     libucrt:fflush.obj
 0004:00000948       $pdata$__acrt_stdio_flush_nolock 0000000140022948     libucrt:fflush.obj
 0004:00000954       $pdata$?common_flush_all@@YAH_N@Z 0000000140022954     libucrt:fflush.obj
 0004:00000960       $pdata$??$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z 0000000140022960     libucrt:fflush.obj
 0004:0000096c       $pdata$?fin$0@?0???$?RV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@V<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_842d9ff0dc9ef11c61343bbaebe7f885>@@AEAV<lambda_c5860995281e5c4ce005b3de8f5874ee>@@$$QEAV<lambda_d90129c13df834fdcbf8d2b88dafcf2d>@@@Z@4HA 000000014002296c     libucrt:fflush.obj
 0004:00000978       $pdata$??$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z 0000000140022978     libucrt:fflush.obj
 0004:00000984       $pdata$?fin$0@?0???$?RV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@V<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_886d6c58226a84441f68b9f2b8217b83>@@AEAV<lambda_ab61a845afdef5b7c387490eaf3616ee>@@$$QEAV<lambda_f7f22ab5edc0698d5f6905b0d3f44752>@@@Z@4HA 0000000140022984     libucrt:fflush.obj
 0004:00000990       $pdata$iswctype            0000000140022990     libucrt:iswctype.obj
 0004:0000099c       $pdata$__acrt_initialize_ptd 000000014002299c     libucrt:per_thread_data.obj
 0004:000009a8       $pdata$__acrt_uninitialize_ptd 00000001400229a8     libucrt:per_thread_data.obj
 0004:000009b4       $pdata$__acrt_getptd       00000001400229b4     libucrt:per_thread_data.obj
 0004:000009c0       $pdata$__acrt_getptd_head  00000001400229c0     libucrt:per_thread_data.obj
 0004:000009cc       $pdata$__acrt_getptd_noexit 00000001400229cc     libucrt:per_thread_data.obj
 0004:000009d8       $pdata$?destroy_fls@@YAXPEAX@Z 00000001400229d8     libucrt:per_thread_data.obj
 0004:000009e4       $pdata$?replace_current_thread_locale_nolock@@YAXQEAU__acrt_ptd@@QEAU__crt_locale_data@@@Z 00000001400229e4     libucrt:per_thread_data.obj
 0004:000009f0       $pdata$?construct_ptd_array@@YAXQEAU__acrt_ptd@@@Z 00000001400229f0     libucrt:per_thread_data.obj
 0004:000009fc       $pdata$?destroy_ptd_array@@YAXQEAU__acrt_ptd@@@Z 00000001400229fc     libucrt:per_thread_data.obj
 0004:00000a08       $pdata$??$?RV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@V<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_0ae27a3a962d80f24befdcbee591983d>@@AEAV<lambda_8d0ee55de4b1038c4002e0adecdf1839>@@$$QEAV<lambda_dc504788e8f1664fe9b84e20bfb512f2>@@@Z 0000000140022a08     libucrt:per_thread_data.obj
 0004:00000a14       $pdata$??$?RV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@V<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_aa87e3671a710a21b5dc78c0bdf72e11>@@AEAV<lambda_92619d2358a28f41a33ba319515a20b9>@@$$QEAV<lambda_6992ecaafeb10aed2b74cb1fae11a551>@@@Z 0000000140022a14     libucrt:per_thread_data.obj
 0004:00000a20       $pdata$??$?RV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@V<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_f2e299630e499de9f9a165e60fcd3db5>@@AEAV<lambda_2ae9d31cdba2644fcbeaf08da7c24588>@@$$QEAV<lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>@@@Z 0000000140022a20     libucrt:per_thread_data.obj
 0004:00000a2c       $pdata$??$?RV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@V<lambda_aa500f224e6afead328df44964fe2772>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_2d41944a1d46af3157314b8a01080d33>@@AEAV<lambda_8f455de75cd7d7f24b4096f044d8b9e6>@@$$QEAV<lambda_aa500f224e6afead328df44964fe2772>@@@Z 0000000140022a2c     libucrt:per_thread_data.obj
 0004:00000a38       $pdata$__acrt_update_locale_info 0000000140022a38     libucrt:locale_update.obj
 0004:00000a44       $pdata$__acrt_update_multibyte_info 0000000140022a44     libucrt:locale_update.obj
 0004:00000a50       $pdata$_fgetwc_nolock      0000000140022a50     libucrt:fgetwc.obj
 0004:00000a5c       $pdata$_fgetc_nolock       0000000140022a5c     libucrt:fgetc.obj
 0004:00000a68       $pdata$__acrt_initialize_lowio 0000000140022a68     libucrt:ioinit.obj
 0004:00000a74       $pdata$__acrt_lowio_ensure_fh_exists$fin$0 0000000140022a74     libucrt:osfinfo.obj
 0004:00000a74       $pdata$__acrt_initialize_lowio$fin$0 0000000140022a74     libucrt:ioinit.obj
 0004:00000a74       $pdata$_alloc_osfhnd$fin$0 0000000140022a74     libucrt:osfinfo.obj
 0004:00000a80       $pdata$__acrt_uninitialize_lowio 0000000140022a80     libucrt:ioinit.obj
 0004:00000a8c       $pdata$?initialize_inherited_file_handles_nolock@@YAXXZ 0000000140022a8c     libucrt:ioinit.obj
 0004:00000a98       $pdata$?initialize_stdio_handles_nolock@@YAXXZ 0000000140022a98     libucrt:ioinit.obj
 0004:00000aa4       $pdata$_towlower_l         0000000140022aa4     libucrt:towlower.obj
 0004:00000ab0       $pdata$__pctype_func       0000000140022ab0     libucrt:ctype.obj
 0004:00000abc       $pdata$__acrt_initialize_locks 0000000140022abc     libucrt:locks.obj
 0004:00000ac8       $pdata$__acrt_uninitialize_locks 0000000140022ac8     libucrt:locks.obj
 0004:00000ad4       $pdata$_malloc_base        0000000140022ad4     libucrt:malloc_base.obj
 0004:00000ae0       $pdata$wcscpy_s            0000000140022ae0     libucrt:wcscpy_s.obj
 0004:00000aec       $pdata$wcsncpy_s           0000000140022aec     libucrt:wcsncpy_s.obj
 0004:00000af8       $pdata$_calloc_base        0000000140022af8     libucrt:calloc_base.obj
 0004:00000b04       $pdata$??$common_expand_argv_wildcards@_W@@YAHQEAPEA_WQEAPEAPEA_W@Z 0000000140022b04     libucrt:argv_wildcards.obj
 0004:00000b10       $pdata$??$copy_and_add_argument_to_buffer@_W@@YAHQEB_W0_KAEAV?$argument_list@_W@?A0x5f5c8891@@@Z 0000000140022b10     libucrt:argv_wildcards.obj
 0004:00000b1c       $pdata$__acrt_update_thread_multibyte_data 0000000140022b1c     libucrt:mbctype.obj
 0004:00000b28       $pdata$__acrt_initialize_multibyte 0000000140022b28     libucrt:mbctype.obj
 0004:00000b34       $pdata$_setmbcp_nolock     0000000140022b34     libucrt:mbctype.obj
 0004:00000b40       $pdata$?getSystemCP@@YAHH@Z 0000000140022b40     libucrt:mbctype.obj
 0004:00000b4c       $pdata$?setSBCS@@YAXPEAU__crt_multibyte_data@@@Z 0000000140022b4c     libucrt:mbctype.obj
 0004:00000b58       $pdata$?update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z 0000000140022b58     libucrt:mbctype.obj
 0004:00000b64       $pdata$?fin$0@?0??update_thread_multibyte_data_internal@@YAPEAU__crt_multibyte_data@@QEAU__acrt_ptd@@QEAPEAU1@@Z@4HA 0000000140022b64     libucrt:mbctype.obj
 0004:00000b70       $pdata$?setmbcp_internal@@YAHH_NQEAU__acrt_ptd@@QEAPEAU__crt_multibyte_data@@@Z 0000000140022b70     libucrt:mbctype.obj
 0004:00000b7c       $pdata$?setSBUpLow@@YAXPEAU__crt_multibyte_data@@@Z 0000000140022b7c     libucrt:mbctype.obj
 0004:00000b88       $pdata$??$?RV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@V<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@?$__crt_seh_guarded_call@X@@QEAAX$$QEAV<lambda_efdfa57d1f175319df784efa44bb7b81>@@AEAV<lambda_5f0a4c1567f8adc6734073e5d1e1b35c>@@$$QEAV<lambda_2e8a7d3640ea6ccb4c2413664c2db6fd>@@@Z 0000000140022b88     libucrt:mbctype.obj
 0004:00000b94       $pdata$__acrt_initialize_command_line 0000000140022b94     libucrt:argv_data.obj
 0004:00000ba0       $pdata$__acrt_WideCharToMultiByte 0000000140022ba0     libucrt:widechartomultibyte.obj
 0004:00000bac       $pdata$__dcrt_get_wide_environment_from_os 0000000140022bac     libucrt:get_environment_from_os.obj
 0004:00000bb8       $pdata$__acrt_get_process_end_policy 0000000140022bb8     libucrt:win_policies.obj
 0004:00000bc4       $pdata$_get_osfhandle      0000000140022bc4     libucrt:osfinfo.obj
 0004:00000bd0       $pdata$_alloc_osfhnd       0000000140022bd0     libucrt:osfinfo.obj
 0004:00000bdc       $pdata$_free_osfhnd        0000000140022bdc     libucrt:osfinfo.obj
 0004:00000be8       $pdata$__acrt_lowio_set_os_handle 0000000140022be8     libucrt:osfinfo.obj
 0004:00000bf4       $pdata$__acrt_lowio_create_handle_array 0000000140022bf4     libucrt:osfinfo.obj
 0004:00000c00       $pdata$__acrt_lowio_destroy_handle_array 0000000140022c00     libucrt:osfinfo.obj
 0004:00000c0c       $pdata$__acrt_lowio_ensure_fh_exists 0000000140022c0c     libucrt:osfinfo.obj
 0004:00000c18       $pdata$__acrt_locale_free_monetary 0000000140022c18     libucrt:initmon.obj
 0004:00000c24       $pdata$__acrt_locale_free_numeric 0000000140022c24     libucrt:initnum.obj
 0004:00000c30       $pdata$__acrt_locale_free_time 0000000140022c30     libucrt:inittime.obj
 0004:00000c3c       $pdata$?free_crt_array_internal@@YAXQEAPEBX_K@Z 0000000140022c3c     libucrt:inittime.obj
 0004:00000c48       $pdata$__acrt_GetStringTypeA 0000000140022c48     libucrt:getstringtypea.obj
 0004:00000c54       $pdata$__acrt_release_locale_ref 0000000140022c54     libucrt:locale_refcounting.obj
 0004:00000c60       $pdata$__acrt_free_locale  0000000140022c60     libucrt:locale_refcounting.obj
 0004:00000c6c       $pdata$__acrt_locale_free_lc_time_if_unreferenced 0000000140022c6c     libucrt:locale_refcounting.obj
 0004:00000c78       $pdata$__acrt_update_thread_locale_data 0000000140022c78     libucrt:locale_refcounting.obj
 0004:00000c84       $pdata$__acrt_update_thread_locale_data$fin$0 0000000140022c84     libucrt:locale_refcounting.obj
 0004:00000c90       $pdata$_updatetlocinfoEx_nolock 0000000140022c90     libucrt:locale_refcounting.obj
 0004:00000c9c       $pdata$__acrt_initialize_winapi_thunks 0000000140022c9c     libucrt:winapi_thunks.obj
 0004:00000ca8       $pdata$__acrt_uninitialize_winapi_thunks 0000000140022ca8     libucrt:winapi_thunks.obj
 0004:00000cb4       $pdata$__acrt_FlsAlloc     0000000140022cb4     libucrt:winapi_thunks.obj
 0004:00000cc0       $pdata$__acrt_FlsFree      0000000140022cc0     libucrt:winapi_thunks.obj
 0004:00000ccc       $pdata$__acrt_FlsGetValue  0000000140022ccc     libucrt:winapi_thunks.obj
 0004:00000cd8       $pdata$__acrt_FlsSetValue  0000000140022cd8     libucrt:winapi_thunks.obj
 0004:00000ce4       $pdata$__acrt_InitializeCriticalSectionEx 0000000140022ce4     libucrt:winapi_thunks.obj
 0004:00000cf0       $pdata$__acrt_LCMapStringEx 0000000140022cf0     libucrt:winapi_thunks.obj
 0004:00000cfc       $pdata$__acrt_LocaleNameToLCID 0000000140022cfc     libucrt:winapi_thunks.obj
 0004:00000d08       $pdata$__acrt_AppPolicyGetProcessTerminationMethodInternal 0000000140022d08     libucrt:winapi_thunks.obj
 0004:00000d14       $pdata$?try_get_function@@YAPEAXW4function_id@?A0x391cf84c@@QEBDQEBW4module_id@2@2@Z 0000000140022d14     libucrt:winapi_thunks.obj
 0004:00000d20       $pdata$_recalloc_base      0000000140022d20     libucrt:recalloc.obj
 0004:00000d2c       $pdata$__acrt_initialize_heap 0000000140022d2c     libucrt:heap_handle.obj
 0004:00000d38       $pdata$__acrt_execute_initializers 0000000140022d38     libucrt:shared_initialization.obj
 0004:00000d44       $pdata$__acrt_execute_uninitializers 0000000140022d44     libucrt:shared_initialization.obj
 0004:00000d50       $pdata$__acrt_get_sigabrt_handler 0000000140022d50     libucrt:signal.obj
 0004:00000d5c       $pdata$raise               0000000140022d5c     libucrt:signal.obj
 0004:00000d68       $pdata$raise$fin$0         0000000140022d68     libucrt:signal.obj
 0004:00000d74       $pdata$??$?RV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@V<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@?$__crt_seh_guarded_call@P6AXH@Z@@QEAAP6AXH@Z$$QEAV<lambda_450d765d439847d4c735a33c368b5fc0>@@AEAV<lambda_44731a7d0e6d81c3e6aa82d741081786>@@$$QEAV<lambda_601a2a7da3b7a96e9554ac7215c4b07c>@@@Z 0000000140022d74     libucrt:signal.obj
 0004:00000d80       $pdata$_mbtowc_l           0000000140022d80     libucrt:mbtowc.obj
 0004:00000d8c       $pdata$_fcloseall          0000000140022d8c     libucrt:closeall.obj
 0004:00000d98       $pdata$_wsopen_s           0000000140022d98     libucrt:open.obj
 0004:00000da4       $pdata$_wsopen_nolock      0000000140022da4     libucrt:open.obj
 0004:00000db0       $pdata$??$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z 0000000140022db0     libucrt:open.obj
 0004:00000dbc       $pdata$?fin$0@?0???$common_sopen_dispatch@_W@@YAHQEB_WHHHQEAHH@Z@4HA 0000000140022dbc     libucrt:open.obj
 0004:00000dc8       $pdata$?decode_options@@YA?AUfile_options@?A0xa9d50aae@@HHH@Z 0000000140022dc8     libucrt:open.obj
 0004:00000dd4       $pdata$?truncate_ctrl_z_if_present@@YAHH@Z 0000000140022dd4     libucrt:open.obj
 0004:00000de0       $pdata$?configure_text_mode@@YAHHUfile_options@?A0xa9d50aae@@HAEAW4__crt_lowio_text_mode@@@Z 0000000140022de0     libucrt:open.obj
 0004:00000dec       $pdata$_commit             0000000140022dec     libucrt:commit.obj
 0004:00000df8       $pdata$??$?RV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@V<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@?$__crt_seh_guarded_call@H@@QEAAH$$QEAV<lambda_a37b2b86f63e897a80ea819b0eb08c01>@@AEAV<lambda_38ce7e780aa69e748d6df282ebc68efe>@@$$QEAV<lambda_99fb1378e971ab6e7edea83e3a7a83a2>@@@Z 0000000140022df8     libucrt:commit.obj
 0004:00000e04       $pdata$_write              0000000140022e04     libucrt:write.obj
 0004:00000e10       $pdata$_write$fin$0        0000000140022e10     libucrt:write.obj
 0004:00000e1c       $pdata$_write_nolock       0000000140022e1c     libucrt:write.obj
 0004:00000e28       $pdata$?write_double_translated_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 0000000140022e28     libucrt:write.obj
 0004:00000e34       $pdata$?write_text_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 0000000140022e34     libucrt:write.obj
 0004:00000e40       $pdata$?write_text_utf16le_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 0000000140022e40     libucrt:write.obj
 0004:00000e4c       $pdata$?write_text_utf8_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z 0000000140022e4c     libucrt:write.obj
 0004:00000e58       $pdata$ungetc              0000000140022e58     libucrt:ungetc.obj
 0004:00000e64       $pdata$ungetc$fin$0        0000000140022e64     libucrt:ungetc.obj
 0004:00000e70       $pdata$_ungetc_nolock      0000000140022e70     libucrt:ungetc.obj
 0004:00000e7c       $pdata$__acrt_stdio_refill_and_read_narrow_nolock 0000000140022e7c     libucrt:_filbuf.obj
 0004:00000e88       $pdata$??$common_refill_and_read_nolock@_W@@YAHV__crt_stdio_stream@@@Z 0000000140022e88     libucrt:_filbuf.obj
 0004:00000e94       $pdata$__acrt_LCMapStringW 0000000140022e94     libucrt:lcmapstringw.obj
 0004:00000ea0       $pdata$qsort               0000000140022ea0     libucrt:qsort.obj
 0004:00000eac       $pdata$4$qsort             0000000140022eac     libucrt:qsort.obj
 0004:00000eb8       $pdata$5$qsort             0000000140022eb8     libucrt:qsort.obj
 0004:00000ec4       $pdata$__acrt_LCMapStringA 0000000140022ec4     libucrt:lcmapstringa.obj
 0004:00000ed0       $pdata$?__acrt_LCMapStringA_stat@@YAHPEAU__crt_locale_pointers@@PEB_WKPEBDHPEADHHH@Z 0000000140022ed0     libucrt:lcmapstringa.obj
 0004:00000edc       $pdata$?initialize_multibyte@@YAHXZ 0000000140022edc     libucrt:multibyte_initializer.obj
 0004:00000ee8       $pdata$__acrt_DownlevelLocaleNameToLCID 0000000140022ee8     libucrt:lcidtoname_downlevel.obj
 0004:00000ef4       $pdata$_msize_base         0000000140022ef4     libucrt:msize.obj
 0004:00000f00       $pdata$_realloc_base       0000000140022f00     libucrt:realloc_base.obj
 0004:00000f0c       $pdata$_isatty             0000000140022f0c     libucrt:isatty.obj
 0004:00000f18       $pdata$?__mbrtowc_utf8@__crt_mbstring@@YA_KPEA_WPEBD_KPEAU_Mbstatet@@@Z 0000000140022f18     libucrt:mbrtowc.obj
 0004:00000f24       $pdata$?__mbsrtowcs_utf8@__crt_mbstring@@YA_KPEA_WPEAPEBD_KPEAU_Mbstatet@@@Z 0000000140022f24     libucrt:mbrtowc.obj
 0004:00000f30       $pdata$_chsize_nolock      0000000140022f30     libucrt:chsize.obj
 0004:00000f3c       $pdata$_read               0000000140022f3c     libucrt:read.obj
 0004:00000f48       $pdata$_read$fin$0         0000000140022f48     libucrt:read.obj
 0004:00000f54       $pdata$_read_nolock        0000000140022f54     libucrt:read.obj
 0004:00000f60       $pdata$?translate_ansi_or_utf8_nolock@@YAHHQEAD_KQEA_W1@Z 0000000140022f60     libucrt:read.obj
 0004:00000f6c       $pdata$??$translate_text_mode_nolock@D@@YAHHQEAD_K@Z 0000000140022f6c     libucrt:read.obj
 0004:00000f78       $pdata$??$translate_text_mode_nolock@_W@@YAHHQEA_W_K@Z 0000000140022f78     libucrt:read.obj
 0004:00000f84       $pdata$??$common_lseek_nolock@_J@@YA_JH_JH@Z 0000000140022f84     libucrt:lseek.obj
 0004:00000f90       $pdata$_putwch_nolock      0000000140022f90     libucrt:putwch.obj
 0004:00000f9c       $pdata$__acrt_stdio_allocate_buffer_nolock 0000000140022f9c     libucrt:_getbuf.obj
 0004:00000fa8       $pdata$?__mbrtoc32_utf8@__crt_mbstring@@YA_KPEA_UPEBD_KPEAU_Mbstatet@@@Z 0000000140022fa8     libucrt:mbrtoc32.obj
 0004:00000fc0       $pdata$__dcrt_lowio_ensure_console_output_initialized 0000000140022fc0     libucrt:initcon.obj
 0004:00000fcc       $pdata$__dcrt_write_console 0000000140022fcc     libucrt:initcon.obj
 0004:00000fd8       $pdata$__dcrt_terminate_console_output 0000000140022fd8     libucrt:initcon.obj
 0004:00000fe4       $pdata$_call_matherr       0000000140022fe4     libucrt:libm_error.obj
 0004:00000ff0       $pdata$_exception_enabled  0000000140022ff0     libucrt:libm_error.obj
 0004:00000ffc       $pdata$_handle_error       0000000140022ffc     libucrt:libm_error.obj
 0004:00001008       $pdata$__acrt_initialize_fma3 0000000140023008     libucrt:fma3_available.obj
 0004:00001014       $pdata$_log_special_common 0000000140023014     libucrt:log_special.obj
 0004:00001020       $pdata$_log10_special      0000000140023020     libucrt:log_special.obj
 0004:00001038       $pdata$_set_errno_from_matherr 0000000140023038     libucrt:fpexcept.obj
 0004:00001044       $pdata$_raise_exc          0000000140023044     libucrt:fpexcept.obj
 0004:00001050       $pdata$_raise_exc_ex       0000000140023050     libucrt:fpexcept.obj
 0004:0000105c       $pdata$_clrfp              000000014002305c     libucrt:fpctrl.obj
 0004:00001068       $pdata$_ctrlfp             0000000140023068     libucrt:fpctrl.obj
 0004:00001074       $pdata$_ctrlfp$filt$0      0000000140023074     libucrt:fpctrl.obj
 0004:00001080       $pdata$_statfp             0000000140023080     libucrt:fpctrl.obj
 0004:0000108c       $pdata$_set_statfp         000000014002308c     libucrt:fpctrl.obj
 0004:00001098       $pdata$__GSHandlerCheckCommon 0000000140023098     LIBCMT:gshandler.obj
 0004:000010a4       $pdata$__GSHandlerCheck    00000001400230a4     LIBCMT:gshandler.obj
 0004:000010b0       $pdata$_IsNonwritableInCurrentImage 00000001400230b0     LIBCMT:pesect.obj
 0004:000010bc       $pdata$_IsNonwritableInCurrentImage$filt$0 00000001400230bc     LIBCMT:pesect.obj
 0004:000010e0       $pdata$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 00000001400230e0     FileProtocolHandler.obj
 0004:000010ec       $pdata$2$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 00000001400230ec     FileProtocolHandler.obj
 0004:000010f8       $pdata$4$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 00000001400230f8     FileProtocolHandler.obj
 0004:00001104       $pdata$5$??$_Reallocate_grow_by@V<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_967c2ed818824c5314a20ec3af46b793>@@_KPEB_W2@Z 0000000140023104     FileProtocolHandler.obj
 0004:00001110       $pdata$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 0000000140023110     FileProtocolHandler.obj
 0004:0000111c       $pdata$2$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 000000014002311c     FileProtocolHandler.obj
 0004:00001128       $pdata$4$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 0000000140023128     FileProtocolHandler.obj
 0004:00001134       $pdata$5$??$_Reallocate_grow_by@V<lambda_19662282d61fd793232134d409f2e084>@@$$V@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_19662282d61fd793232134d409f2e084>@@@Z 0000000140023134     FileProtocolHandler.obj
 0004:00001140       $pdata$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 0000000140023140     FileProtocolHandler.obj
 0004:0000114c       $pdata$2$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 000000014002314c     FileProtocolHandler.obj
 0004:00001158       $pdata$3$?insert@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@_KQEB_W0@Z 0000000140023158     FileProtocolHandler.obj
 0004:00001164       $pdata$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 0000000140023164     FileProtocolHandler.obj
 0004:00001170       $pdata$1$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 0000000140023170     FileProtocolHandler.obj
 0004:0000117c       $pdata$2$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@AEBV12@@Z 000000014002317c     FileProtocolHandler.obj
 0004:00001188       $pdata$?_Xlen@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@SAXXZ 0000000140023188     FileProtocolHandler.obj
 0004:00001194       $pdata$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 0000000140023194     FileProtocolHandler.obj
 0004:000011a0       $pdata$3$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 00000001400231a0     FileProtocolHandler.obj
 0004:000011ac       $pdata$5$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 00000001400231ac     FileProtocolHandler.obj
 0004:000011b8       $pdata$6$??$_Reallocate_grow_by@V<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_1dfe18491bcca09701d8ccb01d0b0af4>@@PEB_W_K@Z 00000001400231b8     FileProtocolHandler.obj
 0004:000011c4       $pdata$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 00000001400231c4     FileProtocolHandler.obj
 0004:000011d0       $pdata$2$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 00000001400231d0     FileProtocolHandler.obj
 0004:000011dc       $pdata$3$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 00000001400231dc     FileProtocolHandler.obj
 0004:000011e8       $pdata$4$??$_Reallocate_for@V<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_3fa8b2c8193a0f3144fc4b1b8f243931>@@PEB_W@Z 00000001400231e8     FileProtocolHandler.obj
 0004:000011f4       $pdata$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 00000001400231f4     FileProtocolHandler.obj
 0004:00001200       $pdata$2$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 0000000140023200     FileProtocolHandler.obj
 0004:0000120c       $pdata$4$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 000000014002320c     FileProtocolHandler.obj
 0004:00001218       $pdata$5$??$_Reallocate_grow_by@V<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K_K_W@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@_KV<lambda_51c4cb9729979bd953fe6d1bff5c73b0>@@_K2_W@Z 0000000140023218     FileProtocolHandler.obj
 0004:00001224       $pdata$??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z 0000000140023224     FileProtocolHandler.obj
 0004:00001230       $pdata$?dtor$0@?0???$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@AEBV10@QEB_W@Z@4HA 0000000140023230     FileProtocolHandler.obj
 0004:0000123c       $pdata$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 000000014002323c     FileProtocolHandler.obj
 0004:00001248       $pdata$1$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 0000000140023248     FileProtocolHandler.obj
 0004:00001254       $pdata$2$??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z 0000000140023254     FileProtocolHandler.obj
 0004:00001260       $pdata$??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ 0000000140023260     FileProtocolHandler.obj
 0004:0000126c       $pdata$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 000000014002326c     FileProtocolHandler.obj
 0004:00001278       $pdata$1$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 0000000140023278     FileProtocolHandler.obj
 0004:00001284       $pdata$2$?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@QEB_W@Z 0000000140023284     FileProtocolHandler.obj
 0004:00001290       $pdata$DialogProc          0000000140023290     FileProtocolHandler.obj
 0004:0000129c       $pdata$?OnInitDialog@@YAHPEAUHWND__@@0_J@Z 000000014002329c     FileProtocolHandler.obj
 0004:000012a8       $pdata$?OnCommand@@YA_JPEAUHWND__@@H0I@Z 00000001400232a8     FileProtocolHandler.obj
 0004:000012b4       $pdata$?dtor$19@?0??OnCommand@@YA_JPEAUHWND__@@H0I@Z@4HA 00000001400232b4     FileProtocolHandler.obj
 0004:000012c0       $pdata$?SetDialogItem@@YAXPEAUHWND__@@PEAVCFileProtocolHandlerService@?A0x9219411d@@@Z 00000001400232c0     FileProtocolHandler.obj
 0004:000012cc       $pdata$wWinMain            00000001400232cc     FileProtocolHandler.obj
 0004:000012d8       $pdata$1$wWinMain          00000001400232d8     FileProtocolHandler.obj
 0004:000012e4       $pdata$3$wWinMain          00000001400232e4     FileProtocolHandler.obj
 0004:000012f0       $pdata$4$wWinMain          00000001400232f0     FileProtocolHandler.obj
 0004:000012fc       $pdata$5$wWinMain          00000001400232fc     FileProtocolHandler.obj
 0004:00001308       $pdata$?HresultErrorMessageBox@@YAXPEAUHWND__@@JAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z 0000000140023308     FileProtocolHandler.obj
 0004:00001314       $pdata$??1?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@QEAA@XZ 0000000140023314     FileProtocolHandler.obj
 0004:00001320       $pdata$??1?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@QEAA@XZ 0000000140023320     FileProtocolHandler.obj
 0004:0000132c       $pdata$?Unregister@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 000000014002332c     FileProtocolHandler.obj
 0004:00001338       $pdata$?Register@CFileProtocolHandlerService@?A0x9219411d@@QEAAJXZ 0000000140023338     FileProtocolHandler.obj
 0004:00001344       $pdata$?GetRegisteredPath@CFileProtocolHandlerService@?A0x9219411d@@QEAA?AU?$pair@JV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@std@@XZ 0000000140023344     FileProtocolHandler.obj
 0004:00001350       $pdata$?ProtocolName@CFileProtocolHandlerService@?A0x9219411d@@QEBA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 0000000140023350     FileProtocolHandler.obj
 0004:0000135c       $pdata$?<lambda_invoker_cdecl>@<lambda_1350e090c1767e0d7e74fd51cceb431d>@@CAHPEAUHWND__@@_J@Z 000000014002335c     FileProtocolHandler.obj
 0004:00001368       $pdata$?OpenFile@CFileProtocolHandlerService@?A0x9219411d@@QEAAJPEB_W@Z 0000000140023368     FileProtocolHandler.obj
 0004:00001374       $pdata$?OpenProtocolKey@CFileProtocolHandlerService@?A0x9219411d@@AEAA?AU?$pair@JV?$unique_ptr@UHKEY__@@P6AJPEAU1@@Z@std@@@std@@XZ 0000000140023374     FileProtocolHandler.obj
 0004:00001380       $pdata$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 0000000140023380     FileProtocolHandler.obj
 0004:0000138c       $pdata$1$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 000000014002338c     FileProtocolHandler.obj
 0004:00001398       $pdata$2$?getModulePath@?A0x9219411d@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@XZ 0000000140023398     FileProtocolHandler.obj
 0004:000013a4       $pdata$__GSHandlerCheck_EH 00000001400233a4     LIBCMT:gshandlereh.obj
 0005:000004e0       $R000000                   00000001400244e0     FileProtocolHandler.res
 0005:00001640       $R001160                   0000000140025640     FileProtocolHandler.res
 0005:000024e8       $R002008                   00000001400264e8     FileProtocolHandler.res
 0005:00002d90       $R0028B0                   0000000140026d90     FileProtocolHandler.res
 0005:000032f8       $R002E18                   00000001400272f8     FileProtocolHandler.res
 0005:00003c08       $R003728                   0000000140027c08     FileProtocolHandler.res
 0005:00007e30       $R007950                   000000014002be30     FileProtocolHandler.res
 0005:0000a3d8       $R009EF8                   000000014002e3d8     FileProtocolHandler.res
 0005:0000b480       $R00AFA0                   000000014002f480     FileProtocolHandler.res
 0005:0000b8e8       $R00B408                   000000014002f8e8     FileProtocolHandler.res
 0005:0000b970       $R00B490                   000000014002f970     FileProtocolHandler.res
 0005:0000cad0       $R00C5F0                   0000000140030ad0     FileProtocolHandler.res
 0005:0000d978       $R00D498                   0000000140031978     FileProtocolHandler.res
 0005:0000e220       $R00DD40                   0000000140032220     FileProtocolHandler.res
 0005:0000e788       $R00E2A8                   0000000140032788     FileProtocolHandler.res
 0005:0000f098       $R00EBB8                   0000000140033098     FileProtocolHandler.res
 0005:000132c0       $R012DE0                   00000001400372c0     FileProtocolHandler.res
 0005:00015868       $R015388                   0000000140039868     FileProtocolHandler.res
 0005:00016910       $R016430                   000000014003a910     FileProtocolHandler.res
 0005:00016d78       $R016898                   000000014003ad78     FileProtocolHandler.res
 0005:00016e00       $R016920                   000000014003ae00     FileProtocolHandler.res
 0005:00016f98       $R016AB8                   000000014003af98     FileProtocolHandler.res
 0005:00017008       $R016B28                   000000014003b008     FileProtocolHandler.res
";
        [Fact]
        public void Test()
        {
            var info = DotMapFileParser.MapFileParser.Parse(_text);
            Assert.True(info.Is64Bit);
            Assert.Equal(0x0000000140000000UL, info.PreferredLoadAddress);
        }
    }
}
