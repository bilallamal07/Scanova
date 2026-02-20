"""Tests for persistence rules."""

from skill_scanner.rules.persistence import (
    AgentConfigTamperRule,
    ScheduledTaskRule,
    ShellProfileRule,
)


class TestScheduledTask:
    def test_crontab(self):
        content = "crontab -e"
        assert len(ScheduledTaskRule().scan_file("f.md", content)) == 1

    def test_systemctl_enable(self):
        content = "systemctl enable malware.service"
        assert len(ScheduledTaskRule().scan_file("f.md", content)) == 1

    def test_launchctl_load(self):
        content = "launchctl load ~/Library/LaunchAgents/evil.plist"
        assert len(ScheduledTaskRule().scan_file("f.md", content)) == 1

    def test_systemctl_status(self):
        content = "systemctl status nginx"
        assert ScheduledTaskRule().scan_file("f.md", content) == []


class TestShellProfile:
    def test_append_bashrc(self):
        content = 'echo "export PATH=..." >> ~/.bashrc'
        assert len(ShellProfileRule().scan_file("f.md", content)) == 1

    def test_overwrite_zshrc(self):
        content = 'echo "malicious" > ~/.zshrc'
        assert len(ShellProfileRule().scan_file("f.md", content)) == 1

    def test_append_profile(self):
        content = "echo 'alias x=y' >> ~/.profile"
        assert len(ShellProfileRule().scan_file("f.md", content)) == 1

    def test_reading_bashrc(self):
        content = "cat ~/.bashrc"
        assert ShellProfileRule().scan_file("f.md", content) == []


class TestAgentConfigTamper:
    def test_write_claude_dir(self):
        content = "echo 'hack' > ~/.claude/settings.json"
        assert len(AgentConfigTamperRule().scan_file("f.md", content)) == 1

    def test_write_cursor_dir(self):
        content = "echo 'x' >> ~/.cursor/config"
        assert len(AgentConfigTamperRule().scan_file("f.md", content)) == 1

    def test_safe_reference(self):
        content = "The config lives at ~/.claude/skills/"
        assert AgentConfigTamperRule().scan_file("f.md", content) == []
