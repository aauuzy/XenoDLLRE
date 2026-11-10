import "pe"

/*
 * Xeno executor detection pack.
 * Built from static analysis of Xeno v1.3.40 and v1.3.65. See docs/defense/DETECTION.md for
 * per-rule scope, validation status, and known false-positive sources.
 *
 * File rules require a PE header. Memory/artifact rules do not, and will therefore also match
 * documentation or threat reports that quote the same strings.
 */

rule Xeno_Executor_DLL_HighConf
{
    meta:
        description = "Xeno core DLL - product-unique strings"
        scope = "file"
        reference = "docs/research/FINDINGS.md"
    strings:
        $s1 = "Xeno is only maintained by Rizve" ascii
        $s2 = "rizve@xeno.onl" ascii
        $s3 = "Intercepted translation module @" ascii
        $s4 = "Attaching in-game using translation module." ascii
        $s5 = "Could not decompress a Xeno resource" ascii
        $s6 = "Xeno Server is Live on http://localhost:" ascii
        $s7 = "https://x3no.pages.dev/ep.zst.enc" ascii
        $s8 = "DO NOT DELETE: BELONGS TO XENO" ascii
        $s9 = "Not allowed to send request to Xeno server" ascii
        $pdb = "Projects\\Xeno\\build\\Release\\net9.0-windows8.0\\Xeno.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Xeno_Signer_Certificate
{
    meta:
        description = "Authenticode signature from the self-signed 'Rizve A' certificate used on Xeno v1.3.65"
        scope = "file"
        sha256_fingerprint = "AEE2FA8DBD1108B7664553143E0ABDF7D41EC87A59CBDB0A2D4D0B84C2B30A21"
        note = "certificate valid 2026-05-10 to 2027-05-10; a renewed certificate will have a new serial"
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.signatures : (
            s.subject contains "Rizve A" and
            s.serial == "3f:da:0d:2c:31:c5:c2:a8:47:90:e6:e2:f2:0d:13:06"
        )
}

rule Xeno_ResourceKey_Initializer
{
    meta:
        description = "Xeno resource XOR key stored as immediates by the CRT initializer"
        scope = "file"
    strings:
        $init = { C7 00 3E FD 50 45 C7 40 04 ED 61 BF CA }
    condition:
        uint16(0) == 0x5A4D and $init
}

rule Xeno_ResourceKey_Memory
{
    meta:
        description = "Xeno resource XOR key as contiguous bytes (heap copy built at runtime)"
        scope = "memory"
    strings:
        $key = { 3E FD 50 45 ED 61 BF CA 57 EF A1 92 D0 07 66 96
                 FD C5 F7 21 12 BD 49 36 7A 3F B3 19 A9 2A F5 BB }
    condition:
        $key
}

rule Xeno_EncryptedResource
{
    meta:
        description = "PE resource of type 8194 whose first 4 bytes decrypt to the zstd frame magic"
        scope = "file"
        note = "version-independent while the key is unchanged; does not depend on payload size"
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0 .. pe.number_of_resources - 1) : (
            pe.resources[i].type == 8194 and
            uint32be(pe.resources[i].offset) == 0x16487FB8
        )
}

rule Xeno_ClientLua_Payload
{
    meta:
        description = "Decrypted Xeno CLIENT.LUA in memory or on disk"
        scope = "memory, file"
    strings:
        $h1 = "CLIENT.LUA -- POST OPEN SOURCE" ascii
        $h2 = "local XENO_PID = \"%XENO_CLIENT_PID%\"" ascii
        $h3 = "shared.__Xeno = Xeno" ascii
        $h4 = "https://x3no.pages.dev/code.lua" ascii
        $h5 = "https://x3no.pages.dev/version.txt" ascii
        $h6 = "local function ExecutionListener()" ascii
        $h7 = "XFS.LockCustomBytecode" ascii
        $h8 = "DO NOT DELETE: BELONGS TO XENO" ascii
    condition:
        3 of them
}

rule Xeno_Server_Protocol
{
    meta:
        description = "Xeno localhost control-plane strings"
        scope = "memory, network capture"
        false_positives = "any document that quotes the protocol, including this repository"
    strings:
        $e1 = "/f?e=" ascii
        $e2 = "/rq?c=" ascii
        $e3 = "/ls?c=" ascii
        $e4 = "%XENO_SERVER_PORT%" ascii
        $e5 = "%XENO_CLIENT_PID%" ascii
        $e6 = "roblox-session-id" ascii
        $e7 = "localhost:3110" ascii
    condition:
        4 of them
}

rule Executor_API_Generic
{
    meta:
        description = "DLL exporting the six-function interface used by Xeno"
        scope = "file"
        confidence = "low - the export names are generic; useful for triage only"
    condition:
        uint16(0) == 0x5A4D and
        pe.exports("Attach") and pe.exports("Execute") and
        pe.exports("Initialize") and pe.exports("GetClients") and
        pe.exports("SetSetting") and pe.exports("Version")
}
