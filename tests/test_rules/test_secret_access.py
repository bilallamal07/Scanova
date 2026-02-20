"""Tests for secret access rules."""

from skill_scanner.rules.secret_access import (
    AIApiKeyRule,
    CredentialPathRule,
    DotenvReadRule,
    PrivateKeyFileRule,
)


class TestDotenvRead:
    def test_cat_env(self):
        content = "cat .env"
        assert len(DotenvReadRule().scan_file("f.md", content)) == 1

    def test_source_env(self):
        content = "source .env"
        assert len(DotenvReadRule().scan_file("f.md", content)) == 1

    def test_unrelated_cat(self):
        content = "cat README.md"
        assert DotenvReadRule().scan_file("f.md", content) == []


class TestCredentialPath:
    def test_ssh_dir(self):
        content = "cat ~/.ssh/id_rsa"
        assert len(CredentialPathRule().scan_file("f.md", content)) == 1

    def test_aws_dir(self):
        content = "cat ~/.aws/credentials"
        assert len(CredentialPathRule().scan_file("f.md", content)) == 1

    def test_gcloud_dir(self):
        content = "cat ~/.config/gcloud/access_tokens.db"
        assert len(CredentialPathRule().scan_file("f.md", content)) == 1

    def test_safe_config_path(self):
        content = "cat ~/.config/some-app/settings.json"
        assert CredentialPathRule().scan_file("f.md", content) == []


class TestAIApiKey:
    def test_anthropic_key(self):
        content = 'echo $ANTHROPIC_API_KEY'
        assert len(AIApiKeyRule().scan_file("f.md", content)) == 1

    def test_openai_key(self):
        content = 'curl -H "Authorization: $OPENAI_API_KEY"'
        assert len(AIApiKeyRule().scan_file("f.md", content)) == 1

    def test_claude_key(self):
        content = "export $CLAUDE_API_KEY"
        assert len(AIApiKeyRule().scan_file("f.md", content)) == 1

    def test_generic_var(self):
        content = "export $MY_VARIABLE"
        assert AIApiKeyRule().scan_file("f.md", content) == []


class TestPrivateKeyFile:
    def test_open_pem(self):
        content = '```python\nf = open("server.pem")\n```'
        assert len(PrivateKeyFileRule().scan_file("f.md", content)) == 1

    def test_open_key(self):
        content = '```python\nopen("/etc/ssl/private/server.key")\n```'
        assert len(PrivateKeyFileRule().scan_file("f.md", content)) == 1

    def test_open_p12(self):
        content = '```python\nopen("cert.p12", "rb")\n```'
        assert len(PrivateKeyFileRule().scan_file("f.md", content)) == 1

    def test_prose_ignored(self):
        content = "You can open the .pem file to inspect it."
        assert PrivateKeyFileRule().scan_file("f.md", content) == []
