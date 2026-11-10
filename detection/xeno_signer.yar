import "pe"

/*
 * Xeno signer certificate rule. Requires YARA built with OpenSSL (pe.signatures); compile it
 * separately from xeno_executor.yar so a YARA build without OpenSSL still loads the main rules.
 *
 * The developer renews a self-signed "CN=Rizve A" certificate each year; the subject has stayed
 * the same across renewals, the serial has not. The rule therefore matches the self-signed
 * subject and records the known serials as metadata.
 */

rule Xeno_Signer_Certificate
{
    meta:
        description = "Authenticode signature from a self-signed 'CN=Rizve A' certificate (Xeno developer)"
        scope = "file"
        serial_v1_3_65 = "3f:da:0d:2c:31:c5:c2:a8:47:90:e6:e2:f2:0d:13:06 (valid 2026-05-10 to 2027-05-10)"
        sha256_v1_3_65 = "AEE2FA8DBD1108B7664553143E0ABDF7D41EC87A59CBDB0A2D4D0B84C2B30A21"
        serial_v1_3_40 = "34:59:8a:72:a3:ae:ea:b8:4a:c8:bd:75:d4:71:bc:9c (valid 2025-09-03 to 2026-09-03)"
        sha256_v1_3_40 = "15EB85335DBA8975A09D1C7B0F3C7D72D1643FC523E1262A3567D150F1BBACED"
        false_positives = "any other file self-signed with the same common name"
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.signatures : (
            s.subject contains "CN=Rizve A" and s.issuer contains "CN=Rizve A"
        )
}
