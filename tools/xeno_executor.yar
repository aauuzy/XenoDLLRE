import "pe"

/*
 * Xeno executor (v1.3.65) detection pack
 * Built from static analysis of TEST.dll — see FINDINGS.md / TECHNICAL_DEEP_DIVE.md
 * Scope: file & memory scanning. Rules are ordered from most to least specific.
 */

rule Xeno_Executor_DLL_HighConf
{
    meta:
        description = "Xeno Roblox executor core DLL (v1.3.65) - unique strings"
        author = "reverse-engineering analysis"
        confidence = "high"
        reference = "FINDINGS.md"
    strings:
        $s1 = "Xeno is only maintained by Rizve" ascii
        $s2 = "rizve@xeno.onl" ascii
        $s3 = "Intercepted translation module @" ascii
        $s4 = "Attaching in-game using translation module." ascii
        $s5 = "Could not decompress a Xeno resource" ascii
        $s6 = "DO NOT DELETE: BELONGS TO XENO" ascii
        $s7 = "Xeno Server is Live on http://localhost:" ascii
        $s8 = "https://x3no.pages.dev/ep.zst.enc" ascii
        $s9 = "Not allowed to send request to Xeno server" ascii
        $pdb = "Projects\\Xeno\\build\\Release\\net9.0-windows8.0\\Xeno.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Xeno_ResourceXorKey
{
    meta:
        description = "Xeno resource XOR key (static dword stores) or raw key bytes"
        confidence = "high"
    strings:
        // raw 32-byte repeating key
        $key = { 3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96
                 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB }
        // the CRT initializer at .text:0x3B10 storing the key as immediates
        $init = { C7 00 3E FD 50 45 C7 40 04 ED 61 BF CA }
    condition:
        any of them
}

rule Xeno_EncryptedResource
{
    meta:
        description = "Xeno encrypted resource blobs (type 8194, shared keystream prefix)"
        confidence = "high"
    strings:
        $r8192 = { 16 48 7F B8 4D 0D 89 C8 57 FB 8F 91 4A 91 2F DD }
        $r8196 = { 16 48 7F B8 4D 95 9C CF 57 5B 0C 93 1A 29 EB A4 }
    condition:
        any of them
}

rule Xeno_ClientLua_Payload
{
    meta:
        description = "Decrypted Xeno CLIENT.LUA in memory or on disk"
        confidence = "high"
    strings:
        $h1 = "v1.3.65 CLIENT.LUA -- POST OPEN SOURCE" ascii
        $h2 = "local XENO_PID = \"%XENO_CLIENT_PID%\"" ascii
        $h3 = "shared.__Xeno = Xeno" ascii
        $h4 = "https://x3no.pages.dev/code.lua" ascii
        $h5 = "https://x3no.pages.dev/version.txt" ascii
        $h6 = "ExecutionListener" ascii
        $h7 = "XFS.LockCustomBytecode" ascii
    condition:
        2 of them
}

rule Xeno_Server_Protocol
{
    meta:
        description = "Xeno localhost control-plane artifacts (memory/network captures)"
        confidence = "medium"
    strings:
        $e1 = "/f?e=" ascii
        $e2 = "/rq?c=" ascii
        $e3 = "%XENO_SERVER_PORT%" ascii
        $e4 = "%XENO_CLIENT_PID%" ascii
        $e5 = "roblox-session-id" ascii
        $e6 = "localhost:3110" ascii
    condition:
        3 of them
}

rule Executor_API_Generic
{
    meta:
        description = "Generic Roblox executor DLL export contract (Xeno family & forks)"
        confidence = "medium - flags the executor API pattern, not Xeno specifically"
    condition:
        uint16(0) == 0x5A4D and
        pe.exports("Attach") and pe.exports("Execute") and
        pe.exports("Initialize") and pe.exports("GetClients") and
        pe.exports("SetSetting") and pe.exports("Version")
}
