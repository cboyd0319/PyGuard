"""Tests for Ruff S (Security) rules implementation."""

from pathlib import Path
import tempfile

from pyguard.lib.ruff_security import check_ruff_security


class TestRuffSecurityRules:
    """Test Ruff S security rules."""

    def test_s101_assert_usage(self):
        """Test S101: assert usage detection."""
        code = """
assert x > 0, "x must be positive"
assert condition
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) == 2
        assert all(v.rule_id == "S101" for v in violations)
        assert "assert" in violations[0].message.lower()

    def test_s102_exec_builtin(self):
        """Test S102: exec() usage detection."""  # DANGEROUS: Avoid exec with untrusted input
        code = """
exec("print('hello')")  # DANGEROUS: Avoid exec with untrusted input
exec(user_input)  # DANGEROUS: Avoid exec with untrusted input
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) == 2
        assert all(v.rule_id == "S102" for v in violations)
        assert "exec" in violations[0].message.lower()

    def test_s104_hardcoded_bind_all_interfaces(self):
        """Test S104: binding to all interfaces."""
        code = """
HOST = "0.0.0.0"
server_host = "::"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) == 2
        assert all(v.rule_id == "S104" for v in violations)

    def test_s105_hardcoded_password_string(self):
        """Test S105: hardcoded password in string."""
        code = """
password = "my_secret_password"  # SECURITY: Use environment variables or config files
db_password = "admin123"
api_token = "abc123def456"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) == 3
        assert all(v.rule_id == "S105" for v in violations)
        assert "hardcoded password" in violations[0].message.lower()

    def test_s105_no_false_positive_on_short_strings(self):
        """Test S105: no false positives on short strings."""
        code = """
password = ""
token = "x"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        # Should not flag short/empty strings
        s105_violations = [v for v in violations if v.rule_id == "S105"]
        assert len(s105_violations) == 0

    def test_s107_hardcoded_password_default(self):
        """Test S107: hardcoded password in function default."""
        code = """
def connect(username, password="default_pwd"):
    # TODO: Add docstring
    pass

def authenticate(token="secret_token_123"):
    # TODO: Add docstring
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) == 2
        assert all(v.rule_id == "S107" for v in violations)

    def test_s108_hardcoded_temp_file(self):
        """Test S108: hardcoded temporary file path."""
        code = """
tmp_file = "/tmp/myapp.tmp"
temp_dir = "C:\\\\temp\\\\data.tmp"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        assert len(violations) >= 2
        s108_violations = [v for v in violations if v.rule_id == "S108"]
        assert len(s108_violations) == 2

    def test_s110_try_except_pass(self):
        """Test S110: try-except-pass detection."""
        code = """
try:
    risky_operation()
except Exception:  # FIXED: Catch specific exceptions
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s110_violations = [v for v in violations if v.rule_id == "S110"]
        assert len(s110_violations) == 1
        assert "pass" in s110_violations[0].message.lower()

    def test_s112_try_except_continue(self):
        """Test S112: try-except-continue detection."""
        code = """
for item in items:
    try:
        process(item)
    except Exception:  # FIXED: Catch specific exceptions
        continue
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s112_violations = [v for v in violations if v.rule_id == "S112"]
        assert len(s112_violations) == 1
        assert "continue" in s112_violations[0].message.lower()

    def test_s113_request_without_timeout(self):
        """Test S113: HTTP request without timeout."""
        code = """
import requests
response = requests.get("https://example.com")
response = requests.post("https://api.example.com", data={})
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s113_violations = [v for v in violations if v.rule_id == "S113"]
        assert len(s113_violations) == 2
        assert "timeout" in s113_violations[0].message.lower()

    def test_s113_request_with_timeout_ok(self):
        """Test S113: request with timeout should not be flagged."""
        code = """
import requests
response = requests.get("https://example.com", timeout=30)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s113_violations = [v for v in violations if v.rule_id == "S113"]
        assert len(s113_violations) == 0

    def test_s301_pickle_usage(self):
        """Test S301: suspicious pickle usage."""
        code = """
import pickle
data = pickle.loads(untrusted_data)  # SECURITY: Don't use pickle with untrusted data
obj = pickle.load(file)  # SECURITY: Don't use pickle with untrusted data
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s301_violations = [v for v in violations if v.rule_id == "S301"]
        assert len(s301_violations) == 2
        assert "pickle" in s301_violations[0].message.lower()

    def test_s302_marshal_usage(self):
        """Test S302: suspicious marshal usage."""
        code = """
import marshal
data = marshal.loads(untrusted_data)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s302_violations = [v for v in violations if v.rule_id == "S302"]
        assert len(s302_violations) == 1

    def test_s306_mktemp_usage(self):
        """Test S306: insecure mktemp usage."""
        code = """
import tempfile
tmp = tempfile.mkstemp(  # FIXED: Using secure mkstemp() instead of mktemp())
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s306_violations = [v for v in violations if v.rule_id == "S306"]
        assert len(s306_violations) == 1
        assert "mktemp" in s306_violations[0].message.lower()

    def test_s307_eval_usage(self):
        """Test S307: eval() usage detection."""  # DANGEROUS: Avoid eval with untrusted input
        code = """
result = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
value = eval("2 + 2")  # DANGEROUS: Avoid eval with untrusted input
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s307_violations = [v for v in violations if v.rule_id == "S307"]
        assert len(s307_violations) == 2
        assert "eval" in s307_violations[0].message.lower()

    def test_s311_non_cryptographic_random(self):
        """Test S311: non-cryptographic random usage."""
        code = """
import random
import secrets  # Use secrets for cryptographic randomness
token = random.randint(1, 1000000)  # SECURITY: Use secrets module for cryptographic randomness
secret = random.random()  # SECURITY: Use secrets module for cryptographic randomness
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s311_violations = [v for v in violations if v.rule_id == "S311"]
        assert len(s311_violations) == 2

    def test_s324_insecure_hash_function(self):
        """Test S324: insecure hash function usage."""
        code = """
import hashlib
hash1 = hashlib.md5(data)  # SECURITY: Consider using SHA256 or stronger
hash2 = hashlib.sha1(data)  # SECURITY: Consider using SHA256 or stronger
hash3 = hashlib.new('md5', data)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s324_violations = [v for v in violations if v.rule_id == "S324"]
        # MD5 and SHA1 should be detected
        assert len(s324_violations) >= 2

    def test_s401_telnetlib_import(self):
        """Test S401: telnetlib import."""
        code = """
import telnetlib
conn = telnetlib.Telnet(host, port)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s401_violations = [v for v in violations if v.rule_id == "S401"]
        assert len(s401_violations) == 1
        assert "telnetlib" in s401_violations[0].message.lower()

    def test_s402_ftplib_import(self):
        """Test S402: ftplib import."""
        code = """
import ftplib
ftp = ftplib.FTP(host)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s402_violations = [v for v in violations if v.rule_id == "S402"]
        assert len(s402_violations) == 1

    def test_s403_pickle_import(self):
        """Test S403: pickle import."""
        code = """
import pickle
import cPickle
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s403_violations = [v for v in violations if v.rule_id == "S403"]
        assert len(s403_violations) == 2

    def test_s405_xml_etree_import(self):
        """Test S405: xml.etree import."""
        code = """
import xml.etree.ElementTree
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s405_violations = [v for v in violations if v.rule_id == "S405"]
        assert len(s405_violations) == 1

    def test_s413_pycrypto_import(self):
        """Test S413: pycrypto import."""
        code = """
import Crypto
from Crypto.Cipher import AES
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s413_violations = [v for v in violations if v.rule_id == "S413"]
        assert len(s413_violations) == 1

    def test_s501_request_no_cert_validation(self):
        """Test S501: request with verify=False."""
        code = """
import requests
response = requests.get("https://example.com", verify=False)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s501_violations = [v for v in violations if v.rule_id == "S501"]
        assert len(s501_violations) == 1
        assert "certificate" in s501_violations[0].message.lower()

    def test_s506_unsafe_yaml_load(self):
        """Test S506: unsafe yaml.load()."""
        code = """
import yaml
data = yaml.safe_load(content)
data2 = yaml.unsafe_load(content)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s506_violations = [v for v in violations if v.rule_id == "S506"]
        assert len(s506_violations) == 2

    def test_s506_safe_yaml_load_ok(self):
        """Test S506: yaml.safe_load() should not be flagged."""
        code = """
import yaml
data = yaml.safe_load(content)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s506_violations = [v for v in violations if v.rule_id == "S506"]
        assert len(s506_violations) == 0

    def test_s602_subprocess_shell_true(self):
        """Test S602: subprocess with shell=True."""
        code = """
import subprocess
subprocess.call("ls -la", shell=True)
subprocess.Popen(cmd, shell=True)  # Best Practice: Use 'with' statement
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s602_violations = [v for v in violations if v.rule_id == "S602"]
        assert len(s602_violations) == 2
        assert "shell=True" in s602_violations[0].message

    def test_s603_subprocess_string_arg(self):
        """Test S603: subprocess with string argument."""
        code = """
import subprocess
subprocess.run("ls -la")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s603_violations = [v for v in violations if v.rule_id == "S603"]
        assert len(s603_violations) == 1

    def test_s303_insecure_hash_sha(self):
        """Test S303: insecure hash usage (SHA)."""
        code = """
import hashlib
hash1 = hashlib.sha(data)
hash2 = hashlib.new('sha', data)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s303_violations = [v for v in violations if v.rule_id == "S303"]
        assert len(s303_violations) >= 1  # Should detect at least one

    def test_s308_mark_safe_usage(self):
        """Test S308: Django mark_safe usage."""
        code = """
from django.utils.safestring import mark_safe
html = mark_safe(user_input)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s308_violations = [v for v in violations if v.rule_id == "S308"]
        assert len(s308_violations) == 1

    def test_s310_urlopen_usage(self):
        """Test S310: urllib.urlopen usage."""
        code = """
import urllib.request
response = urllib.request.urlopen("http://example.com")  # Best Practice: Use 'with' statement
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s310_violations = [v for v in violations if v.rule_id == "S310"]
        assert len(s310_violations) == 1

    def test_s312_telnetlib_usage(self):
        """Test S312: telnetlib usage in function calls."""
        code = """
import telnetlib
tn = telnetlib.Telnet(host)
tn.read_until(b"login: ")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s312_violations = [v for v in violations if v.rule_id == "S312"]
        # Should detect telnetlib.Telnet and telnetlib.read_until
        assert len(s312_violations) >= 1

    def test_s313_xml_etree_usage(self):
        """Test S313: xml.etree usage."""
        code = """
import xml.etree.ElementTree
tree = xml.etree.ElementTree.parse('file.xml')
root = xml.etree.ElementTree.fromstring(xml_string)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s313_violations = [v for v in violations if v.rule_id == "S313"]
        assert len(s313_violations) >= 1

    def test_s323_unverified_ssl_context(self):
        """Test S323: ssl._create_unverified_context."""
        code = """
import ssl
context = ssl._create_unverified_context()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s323_violations = [v for v in violations if v.rule_id == "S323"]
        assert len(s323_violations) == 1

    def test_s604_subprocess_call_shell_true(self):
        """Test S604: subprocess.call with shell=True."""
        code = """
import subprocess
subprocess.call("ls -la", shell=True)
subprocess.check_call(cmd, shell=True)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s604_violations = [v for v in violations if v.rule_id == "S604"]
        assert len(s604_violations) >= 1

    def test_s605_os_system_usage(self):
        """Test S605: os.system usage."""
        code = """
import os
os.system("ls -la")  # SECURITY: Use subprocess.run() instead
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s605_violations = [v for v in violations if v.rule_id == "S605"]
        assert len(s605_violations) == 1

    def test_s606_os_popen_usage(self):
        """Test S606: os.popen usage."""
        code = """
import os
output = os.popen("ls -la").read()  # Best Practice: Use 'with' statement
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s606_violations = [v for v in violations if v.rule_id == "S606"]
        assert len(s606_violations) == 1

    def test_s608_sql_injection(self):
        """Test S608: SQL injection via string formatting."""
        code = """
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s608_violations = [v for v in violations if v.rule_id == "S608"]
        assert len(s608_violations) >= 1

    def test_s701_jinja2_autoescape_false(self):
        """Test S701: Jinja2 autoescape=False."""
        code = """
import jinja2
env = jinja2.Environment(autoescape=False)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        s701_violations = [v for v in violations if v.rule_id == "S701"]
        assert len(s701_violations) == 1

    def test_no_violations_on_safe_code(self):
        """Test that safe code produces no security violations."""
        code = """
import json
import hashlib
from pathlib import Path

def process_data(data_file: Path):
    '''Process data safely.'''
    with open(data_file) as f:
        data = json.load(f)

    # Use secure hash
    hash_value = hashlib.sha256(data.encode()).hexdigest()

    return hash_value
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            violations = check_ruff_security(Path(f.name))

        # Should have no S-code violations
        assert len(violations) == 0
