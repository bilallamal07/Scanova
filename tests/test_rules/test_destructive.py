"""Tests for destructive operations rules."""

from skill_scanner.rules.destructive import (
    DatabaseDropRule,
    DiskOperationRule,
    GitForceRule,
    RecursiveDeleteRule,
)


class TestRecursiveDelete:
    def test_rm_rf_root(self):
        content = "rm -rf / "
        assert len(RecursiveDeleteRule().scan_file("f.md", content)) == 1

    def test_rm_rf_home(self):
        content = "rm -rf ~/"
        assert len(RecursiveDeleteRule().scan_file("f.md", content)) == 1

    def test_rm_rf_variable(self):
        content = "rm -rf $SOME_DIR"
        assert len(RecursiveDeleteRule().scan_file("f.md", content)) == 1

    def test_rm_single_file(self):
        content = "rm file.txt"
        assert RecursiveDeleteRule().scan_file("f.md", content) == []

    def test_rm_rf_specific_dir(self):
        content = "rm -rf ./build"
        assert RecursiveDeleteRule().scan_file("f.md", content) == []


class TestDatabaseDrop:
    def test_drop_table(self):
        content = "DROP TABLE users;"
        assert len(DatabaseDropRule().scan_file("f.md", content)) == 1

    def test_drop_database(self):
        content = "DROP DATABASE production;"
        assert len(DatabaseDropRule().scan_file("f.md", content)) == 1

    def test_truncate_table(self):
        content = "TRUNCATE TABLE logs;"
        assert len(DatabaseDropRule().scan_file("f.md", content)) == 1

    def test_select_safe(self):
        content = "SELECT * FROM users;"
        assert DatabaseDropRule().scan_file("f.md", content) == []

    def test_case_insensitive(self):
        content = "drop table users;"
        assert len(DatabaseDropRule().scan_file("f.md", content)) == 1


class TestGitForce:
    def test_force_push(self):
        content = "git push origin main --force"
        assert len(GitForceRule().scan_file("f.md", content)) == 1

    def test_normal_push(self):
        content = "git push origin main"
        assert GitForceRule().scan_file("f.md", content) == []


class TestDiskOperation:
    def test_mkfs(self):
        content = "mkfs.ext4 /dev/sda1"
        assert len(DiskOperationRule().scan_file("f.md", content)) == 1

    def test_dd(self):
        content = "dd if=/dev/zero of=/dev/sda bs=1M"
        assert len(DiskOperationRule().scan_file("f.md", content)) == 1

    def test_safe_dd_to_file(self):
        # dd without if= should not match
        content = "dd of=backup.img bs=4M"
        assert DiskOperationRule().scan_file("f.md", content) == []
