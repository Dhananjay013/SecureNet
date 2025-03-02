rule win_privateloader 
{
  meta:
    author      = "andretavare5"
    description = "Detects PrivateLoader malware."
    org         = "Bitsight"
    date        = "2024-01-11"
    sample      = "6f7f9de3238003897f35b86caf942f088f14e88ecb1a5a1329ef5a7d421f7008"
    reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.privateloader"
    license     = "CC BY-NC-SA 4.0"
    
  strings:
    $hdr   = "Content-Type: application/x-www-form-urlencoded" wide ascii
    $dom1  = "ipinfo.io" wide ascii
    $dom2  = "db-ip.com" wide ascii
    $dom3  = "maxmind.com" wide ascii
    $dom4  = "ipgeolocation.io" wide ascii
    $ua1   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" wide ascii
    $ua2   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36" wide ascii
    $instr = {66 0F EF (4?|8?)} // pxor xmm(1/0) - str chunk decryption
                              
  condition:
    uint16(0) == 0x5A4D and // MZ header
    filesize > 100KB and filesize < 10MB and
    $hdr and
    any of ($dom*) and
    any of ($ua*) and
    #instr > 100
}