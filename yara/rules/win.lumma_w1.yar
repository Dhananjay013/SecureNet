rule win_lumma_w1 {
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Detects obfuscation methods observed in Lumma Stealer Payloads"
		sha_256 = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		sha_256 = "7f18cf601b818b11068bb8743283ae378f547a1581682ea3cc163186aae7c55d"
		sha_256 = "03796740db48a98a4438c36d7b8c14b0a871bf8c692e787f1bf093b2d584999f"
		date = "2023-09-13"
		source = "https://github.com/embee-research/Yara-detection-rules/blob/main/Rules/win_lumma%20_simple.yar"
        yarahub_uuid = "39c32477-9a80-485b-b17a-4adf05f66cf8"
       	yarahub_license = "CC BY-NC 4.0"
        malpedia_family = "win.lumma"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        malpedia_version = "20230918"
        malpedia_license = ""
        malpedia_sharing = "TLP:WHITE"
	strings:

		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0) == 0x5a4d
		and
		filesize < 5000KB
		and
		(all of ($o*))


}
