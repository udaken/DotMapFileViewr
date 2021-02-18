using System;
using System.IO;
using Xunit;

namespace test
{
    public class CeExe
    {
        const string _text = @" vdec_dump

 Timestamp is 601a0078 (Wed Feb 03 10:46:32 2021)

 Preferred load address is 00010000

 Start         Length     Name                   Class
 0001:00000000 00001e3cH .text                   CODE
 0002:00000000 00000004H .CRT$XCA                DATA
 0002:00000004 00000004H .CRT$XCZ                DATA
 0002:00000008 00000004H .CRT$XIA                DATA
 0002:0000000c 00000004H .CRT$XIZ                DATA
 0002:00000010 00000004H .CRT$XPA                DATA
 0002:00000014 00000004H .CRT$XPZ                DATA
 0002:00000018 00000004H .CRT$XTA                DATA
 0002:0000001c 00000004H .CRT$XTZ                DATA
 0002:00000020 000007e4H .rdata                  DATA
 0002:00000804 0000005dH .rdata$debug            DATA
 0002:00000864 00000024H .xdata                  DATA
 0002:00000888 00000014H .idata$2                DATA
 0002:0000089c 00000014H .idata$3                DATA
 0002:000008b0 00000064H .idata$4                DATA
 0002:00000914 0000000cH .idata$6                DATA
 0002:00000920 00000000H .edata                  DATA
 0003:00000000 00000064H .idata$5                DATA
 0003:00000064 00000008H .data                   DATA
 0003:0000006c 0000001cH .bss                    DATA
 0004:00000000 000001d8H .pdata                  DATA

  Address         Publics by Value              Rva+Base       Lib:Object

 0000:00000000       ___safe_se_handler_count   00000000     <absolute>
 0000:00000000       ___safe_se_handler_table   00000000     <absolute>
 0001:00000008       ?dump_ML86203@@YAXXZ       00011008 f   vdec_dump.obj
 0001:000001ac       ?dump_ML86207@@YAXXZ       000111ac f   vdec_dump.obj
 0001:00000598       wmain                      00011598 f   vdec_dump.obj
 0001:000005d4       ?Read@FileHandle@SM@@QAAJPAXKPAK@Z 000115d4 f i vdec_dump.obj
 0001:000006a0       ?OpenCh1@SM_I2CDriverHandle@@QAAJXZ 000116a0 f i vdec_dump.obj
 0001:000007a8       ?SetSubAddress@SM_I2CDriverHandle@@QAAJE@Z 000117a8 f i vdec_dump.obj
 0001:00000850       ?DeviceIoControl@DriverHandle@SM@@QAAJKPAXK0KPAK@Z 00011850 f i vdec_dump.obj
 0001:00000934       ??0SM_I2CDriverHandle@@QAA@XZ 00011934 f i vdec_dump.obj
 0001:00000974       ??0DriverHandle@SM@@QAA@XZ 00011974 f i vdec_dump.obj
 0001:000009c0       ??0FileHandle@SM@@QAA@PAX@Z 000119c0 f i vdec_dump.obj
 0001:00000a04       ??_GFileHandle@SM@@UAAPAXI@Z 00011a04 f i vdec_dump.obj
 0001:00000a04       ??_EFileHandle@SM@@UAAPAXI@Z 00011a04 f i vdec_dump.obj
 0001:00000a44       ??1FileHandle@SM@@UAA@XZ   00011a44 f i vdec_dump.obj
 0001:00000a5c       ??_EDriverHandle@SM@@UAAPAXI@Z 00011a5c f i vdec_dump.obj
 0001:00000a5c       ??_GDriverHandle@SM@@UAAPAXI@Z 00011a5c f i vdec_dump.obj
 0001:00000a9c       ??1DriverHandle@SM@@UAA@XZ 00011a9c f i vdec_dump.obj
 0001:00000ab4       ??1SM_I2CDriverHandle@@UAA@XZ 00011ab4 f i vdec_dump.obj
 0001:00000acc       ??_ESM_I2CDriverHandle@@UAAPAXI@Z 00011acc f i vdec_dump.obj
 0001:00000acc       ??_GSM_I2CDriverHandle@@UAAPAXI@Z 00011acc f i vdec_dump.obj
 0001:00000b14       ?Write@SM_I2CDriverHandle@@QAAJPBXKPAK@Z 00011b14 f i vdec_dump.obj
 0001:00000c48       wmemset                    00011c48 f i vdec_dump.obj
 0001:00000cac       ?Write@FileHandle@SM@@QAAJPBXKPAK@Z 00011cac f i vdec_dump.obj
 0001:00000d78       wmemcpy                    00011d78 f i vdec_dump.obj
 0001:00000dec       ?invalidHandleValue@?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@SAPAXXZ 00011dec f i vdec_dump.obj
 0001:00000e30       ??0?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@QAA@PAX@Z 00011e30 f i vdec_dump.obj
 0001:00000e74       ??1?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@UAA@XZ 00011e74 f i vdec_dump.obj
 0001:00000eb8       ?value@?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@QBAABQAXXZ 00011eb8 f i vdec_dump.obj
 0001:00000ee0       ?Reset@?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@QAA_NPAX@Z 00011ee0 f i vdec_dump.obj
 0001:00000f4c       ??_E?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@UAAPAXI@Z 00011f4c f i vdec_dump.obj
 0001:00000f4c       ??_G?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@UAAPAXI@Z 00011f4c f i vdec_dump.obj
 0001:00000f8c       ?Close@?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@QAA_NXZ 00011f8c f i vdec_dump.obj
 0001:00001040       ?IsInvalid@?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@QBA_NXZ 00012040 f i vdec_dump.obj
 0001:0000109c       ??$?BU_OVERLAPPED@@@nullptr_t@std@@QBAPAU_OVERLAPPED@@XZ 0001209c f i vdec_dump.obj
 0001:000010c0       ??$?BX@nullptr_t@std@@QBAPAXXZ 000120c0 f i vdec_dump.obj
 0001:000010e4       ??$?BK@nullptr_t@std@@QBAPAKXZ 000120e4 f i vdec_dump.obj
 0001:00001108       ??$?BU_SECURITY_ATTRIBUTES@@@nullptr_t@std@@QBAPAU_SECURITY_ATTRIBUTES@@XZ 00012108 f i vdec_dump.obj
 0001:0000112c       NKDbgPrintfW               0001212c f   coredll:COREDLL.dll
 0001:0000113c       GetLastError               0001213c f   coredll:COREDLL.dll
 0001:0000114c       ReadFile                   0001214c f   coredll:COREDLL.dll
 0001:0000115c       CreateFileW                0001215c f   coredll:COREDLL.dll
 0001:0000116c       DeviceIoControl            0001216c f   coredll:COREDLL.dll
 0001:0000117c       WriteFile                  0001217c f   coredll:COREDLL.dll
 0001:0000118c       OutputDebugStringW         0001218c f   coredll:COREDLL.dll
 0001:0000119c       CloseHandle                0001219c f   coredll:COREDLL.dll
 0001:0000162c       mainWCRTStartup            0001262c f   corelibc:mainwcrt.obj
 0001:0000164c       printf                     0001264c f   corelibc:COREDLL.dll
 0001:0000165c       __security_init_cookie     0001265c f   corelibc:seccinit.obj
 0001:000016a8       __GSHandlerCheckCommon     000126a8 f   corelibc:gshandler.obj
 0001:000016e4       __GSHandlerCheck           000126e4 f   corelibc:gshandler.obj
 0001:00001704       memset                     00012704 f   corelibc:COREDLL.dll
 0001:00001714       __security_check_cookie    00012714 f   corelibc:armsecgs.obj
 0001:00001724       __gsfailure                00012724     corelibc:armsecgs.obj
 0001:00001768       ??3@YAXPAX@Z               00012768 f   corelibc:COREDLL.dll
 0001:00001778       wcslen                     00012778 f   corelibc:COREDLL.dll
 0001:00001788       free                       00012788 f   corelibc:COREDLL.dll
 0001:00001798       iswctype                   00012798 f   corelibc:COREDLL.dll
 0001:000017a8       malloc                     000127a8 f   corelibc:COREDLL.dll
 0001:000017b8       memcpy                     000127b8 f   corelibc:COREDLL.dll
 0001:000017c8       _XcptFilter                000127c8 f   corelibc:COREDLL.dll
 0001:00001898       exit                       00012898 f   corelibc:cexit.obj
 0001:000018a4       _exit                      000128a4 f   corelibc:cexit.obj
 0001:000018dc       _cexit                     000128dc f   corelibc:cexit.obj
 0001:000018ec       _c_exit                    000128ec f   corelibc:cexit.obj
 0001:00001910       _initterm                  00012910 f   corelibc:crt0dat.obj
 0001:0000193c       _cinit                     0001293c f   corelibc:crt0dat.obj
 0001:0000199c       _onexit                    0001299c f   corelibc:onexit.obj
 0001:00001a6c       atexit                     00012a6c f   corelibc:onexit.obj
 0001:00001a84       __GSHandlerCheck_SEH       00012a84 f   corelibc:gshandlerseh.obj
 0001:00001ad0       __security_gen_cookie2     00012ad0 f   corelibc:COREDLL.dll
 0001:00001ae0       __report_gsfailure         00012ae0 f   corelibc:COREDLL.dll
 0001:00001af0       GetCurrentProcess          00012af0 f i corelibc:exitproc_proxy.obj
 0001:00001af8       __crt_ExitProcess          00012af8 f   corelibc:exitproc_proxy.obj
 0001:00001b04       realloc                    00012b04 f   corelibc:COREDLL.dll
 0001:00001b14       _msize                     00012b14 f   corelibc:COREDLL.dll
 0001:00001b24       __C_specific_handler       00012b24 f   corelibc:COREDLL.dll
 0001:00001b34       GetModuleFileNameW         00012b34 f   coredll:COREDLL.dll
 0001:00001b44       TerminateProcess           00012b44 f   coredll:COREDLL.dll
 0002:00000000       __xc_a                     00013000     corelibc:crt0init.obj
 0002:00000004       __xc_z                     00013004     corelibc:crt0init.obj
 0002:00000008       __xi_a                     00013008     corelibc:crt0init.obj
 0002:0000000c       __xi_z                     0001300c     corelibc:crt0init.obj
 0002:00000010       __xp_a                     00013010     corelibc:crt0init.obj
 0002:00000014       __xp_z                     00013014     corelibc:crt0init.obj
 0002:00000018       __xt_a                     00013018     corelibc:crt0init.obj
 0002:0000001c       __xt_z                     0001301c     corelibc:crt0init.obj
 0002:00000244       ?debug@SM_I2CDriverHandle@@0HB 00013244     vdec_dump.obj
 0002:00000248       ?BIT_WRITE@SM_I2CDriverHandle@@2EB 00013248     vdec_dump.obj
 0002:00000249       ?BIT_READ@SM_I2CDriverHandle@@2EB 00013249     vdec_dump.obj
 0002:00000250       ??_C@_1M@DENAJNJJ@?$AAI?$AA2?$AAC?$AA2?$AA?3?$AA?$AA@ 00013250     vdec_dump.obj
 0002:0000025c       ??_C@_1CG@GFGALMAH@?$AA?$FL?$AAS?$AAM?$AA?$FN?$AA?5?$AA?$DM?$AA?$CF?$AAS?$AA?$DO?$AA?5?$AA?$FL?$AA?$CF?$AA0?$AA2?$AAX?$AA?$FN?$AA?$AN?$AA?6?$AA?$AA@ 0001325c     vdec_dump.obj
 0002:00000284       ??_C@_0CC@HCPHHGDA@SM_I2CDriverHandle?3?3SetSubAddres@ 00013284     vdec_dump.obj
 0002:000002a8       ??_7SM_I2CDriverHandle@@6B@ 000132a8     vdec_dump.obj
 0002:000002ac       ??_7DriverHandle@SM@@6B@   000132ac     vdec_dump.obj
 0002:000002b0       ??_7FileHandle@SM@@6B@     000132b0     vdec_dump.obj
 0002:000002b8       ??_C@_1IA@IALAHAFP@?$AA?$FL?$AAS?$AAM?$AA?$FN?$AA?5?$AA?$DM?$AA?$CF?$AAS?$AA?$DO?$AA?5?$AAR?$AAe?$AAs?$AAu?$AAl?$AAt?$AA?5?$AAo?$AAf?$AA?5?$AAW?$AAr?$AAi?$AAt?$AAe?$AAF?$AAi?$AAl?$AAe?$AA?5?$AA?5?$AA?$CI@ 000132b8     vdec_dump.obj
 0002:00000338       ??_C@_1KI@EJJHAHNA@?$AA?$FL?$AAS?$AAM?$AA?$FN?$AA?5?$AA?$DM?$AA?$CF?$AAS?$AA?$DO?$AA?5?$AAC?$AAa?$AAl?$AAl?$AA?5?$AAW?$AAr?$AAi?$AAt?$AAe?$AAF?$AAi?$AAl?$AAe?$AA?$CI?$AAn?$AAN?$AAu?$AAm?$AAb?$AAe?$AAr@ 00013338     vdec_dump.obj
 0002:000003e0       ??_C@_0BK@DNEDJFKP@SM_I2CDriverHandle?3?3Write?$AA@ 000133e0     vdec_dump.obj
 0002:00000800       ??_7?$Win32Handle@PAX$1?CloseHandle@@YAHPAX@Z$0A@@SM@@6B@ 00013800     vdec_dump.obj
 0002:00000888       __IMPORT_DESCRIPTOR_COREDLL 00013888     coredll:COREDLL.dll
 0002:0000089c       __NULL_IMPORT_DESCRIPTOR   0001389c     coredll:COREDLL.dll
 0003:00000000       __imp_NKDbgPrintfW         00014000     coredll:COREDLL.dll
 0003:00000004       __imp_GetLastError         00014004     coredll:COREDLL.dll
 0003:00000008       __imp_ReadFile             00014008     coredll:COREDLL.dll
 0003:0000000c       __imp_CreateFileW          0001400c     coredll:COREDLL.dll
 0003:00000010       __imp_DeviceIoControl      00014010     coredll:COREDLL.dll
 0003:00000014       __imp_WriteFile            00014014     coredll:COREDLL.dll
 0003:00000018       __imp_OutputDebugStringW   00014018     coredll:COREDLL.dll
 0003:0000001c       __imp_CloseHandle          0001401c     coredll:COREDLL.dll
 0003:00000020       __imp_printf               00014020     corelibc:COREDLL.dll
 0003:00000024       __imp_memset               00014024     corelibc:COREDLL.dll
 0003:00000028       __imp_??3@YAXPAX@Z         00014028     corelibc:COREDLL.dll
 0003:0000002c       __imp_wcslen               0001402c     corelibc:COREDLL.dll
 0003:00000030       __imp_free                 00014030     corelibc:COREDLL.dll
 0003:00000034       __imp_iswctype             00014034     corelibc:COREDLL.dll
 0003:00000038       __imp_malloc               00014038     corelibc:COREDLL.dll
 0003:0000003c       __imp_memcpy               0001403c     corelibc:COREDLL.dll
 0003:00000040       __imp__XcptFilter          00014040     corelibc:COREDLL.dll
 0003:00000044       __imp___security_gen_cookie2 00014044     corelibc:COREDLL.dll
 0003:00000048       __imp___report_gsfailure   00014048     corelibc:COREDLL.dll
 0003:0000004c       __imp_realloc              0001404c     corelibc:COREDLL.dll
 0003:00000050       __imp__msize               00014050     corelibc:COREDLL.dll
 0003:00000054       __imp___C_specific_handler 00014054     corelibc:COREDLL.dll
 0003:00000058       __imp_GetModuleFileNameW   00014058     coredll:COREDLL.dll
 0003:0000005c       __imp_TerminateProcess     0001405c     coredll:COREDLL.dll
 0003:00000060       \177COREDLL_NULL_THUNK_DATA 00014060     coredll:COREDLL.dll
 0003:00000064       __security_cookie          00014064     corelibc:seccinit.obj
 0003:00000068       __security_cookie_complement 00014068     corelibc:seccinit.obj
 0003:00000070       __argc                     00014070     corelibc:crtstrtg.obj
 0003:00000074       __wargv                    00014074     corelibc:crtstrtg.obj
 0003:00000078       __argv                     00014078     corelibc:crtstrtg.obj
 0003:0000007c       _exitflag                  0001407c     corelibc:cexit.obj
 0003:00000080       __onexitend                00014080     <common>
 0003:00000084       __onexitbegin              00014084     <common>

 entry point at        0001:0000162c

 Static symbols

 0001:000003a8       ?AppendDumpToStr@?A0x31d6894a@@YAXPA_WIPBXI@Z 000113a8 f   vdec_dump.obj
 0001:00000410       ?DumpToStr@?A0x31d6894a@@YAXPA_WIPBXI@Z 00011410 f   vdec_dump.obj
 0001:000011ac       ?crtstart_FreeArguments@@YAXXZ 000121ac f   corelibc:mainwcrt.obj
 0001:000011c8       ?crtstart_SkipWhiteW@@YAHPBG@Z 000121c8 f   corelibc:mainwcrt.obj
 0001:00001208       ?crtstart_SkipNonWhiteQuotesW@@YAHPBG@Z 00012208 f   corelibc:mainwcrt.obj
 0001:00001270       ?crtstart_RemoveQuotesW@@YAXPAG@Z 00012270 f   corelibc:mainwcrt.obj
 0001:0000129c       ?crtstart_CountSpaceW@@YAXAAH0PBG@Z 0001229c f   corelibc:mainwcrt.obj
 0001:00001374       ?crtstart_ParseArgsWW@@YAHPBG0AAHAAPAPAG@Z 00012374 f   corelibc:mainwcrt.obj
 0001:00001538       ?mainCRTStartupHelper@@YAXPAUHINSTANCE__@@PBG@Z 00012538 f   corelibc:mainwcrt.obj
 0001:000017d8       doexit                     000127d8 f   corelibc:cexit.obj
";
        [Fact]
        public void Test()
        {
            var info = DotMapFileParser.MapFileParser.Parse(_text);
            Assert.False(info.Is64Bit);
            Assert.Equal(0x00010000UL, info.PreferredLoadAddress);
        }
    }
}
