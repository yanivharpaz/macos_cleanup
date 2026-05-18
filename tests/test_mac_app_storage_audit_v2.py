import csv
import io
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mac_app_storage_audit_v2 as audit


class FakeSizeCache:
    def __init__(self, sizes=None):
        self.sizes = {str(path): kb for path, kb in (sizes or {}).items()}
        self.errors = {}

    def du_kb(self, path):
        return self.sizes.get(str(path), 0)


class NonClosingStringIO(io.StringIO):
    def __exit__(self, exc_type, exc_value, traceback):
        return False


@contextmanager
def patched_library(home):
    old_home = audit.HOME
    old_lib = audit.LIB
    old_cache_roots = audit.CACHE_ROOTS
    old_state_roots = audit.STATE_ROOTS
    old_all_roots = audit.ALL_LIBRARY_ROOTS

    audit.HOME = home
    audit.LIB = home / "Library"
    audit.CACHE_ROOTS = [
        audit.LIB / "Caches",
        audit.LIB / "HTTPStorages",
        audit.LIB / "WebKit",
        audit.LIB / "Logs",
        audit.LIB / "Saved Application State",
    ]
    audit.STATE_ROOTS = [
        audit.LIB / "Application Support",
        audit.LIB / "Containers",
        audit.LIB / "Group Containers",
    ]
    audit.ALL_LIBRARY_ROOTS = audit.CACHE_ROOTS + audit.STATE_ROOTS

    try:
        yield audit.LIB
    finally:
        audit.HOME = old_home
        audit.LIB = old_lib
        audit.CACHE_ROOTS = old_cache_roots
        audit.STATE_ROOTS = old_state_roots
        audit.ALL_LIBRARY_ROOTS = old_all_roots


class StorageAuditTests(unittest.TestCase):
    def test_summarize_splits_deep_container_cache_without_double_counting(self):
        home = Path("/virtual/home")
        with patched_library(home) as lib:
            container = lib / "Containers" / "com.example.Widget"
            cache_dir = container / "Data" / "Library" / "Caches"
            support_dir = container / "Data" / "Library" / "Application Support"
            app_path = home / "Applications" / "Widget.app"
            existing_dirs = {container, container / "Data", container / "Data" / "Library", cache_dir, support_dir}

            def fake_walk(root):
                self.assertEqual(Path(root), container)
                yield str(container), ["Data"], []
                yield str(container / "Data"), ["Library"], []
                yield str(container / "Data" / "Library"), ["Caches", "Application Support"], []
                yield str(cache_dir), [], []
                yield str(support_dir), [], []

            app = audit.AppInfo("Widget", "com.example.Widget", app_path, 0)
            app.candidates[container] = audit.PathCandidate(
                container,
                "support/container",
                "bundle-id container",
            )
            app.candidates[cache_dir] = audit.PathCandidate(
                cache_dir,
                "cache-like",
                "container cache",
            )

            sizes = {
                container: 100,
                cache_dir: 35,
            }
            with mock.patch.object(Path, "exists", lambda path: path in existing_dirs), \
                    mock.patch.object(Path, "is_dir", lambda path: path in existing_dirs), \
                    mock.patch.object(audit.os, "walk", fake_walk), \
                    mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache(sizes)):
                cache_kb, support_kb, details = audit.summarize_app_paths(app)

            self.assertEqual(cache_kb, 35)
            self.assertEqual(support_kb, 65)
            self.assertEqual(cache_kb + support_kb, 100)
            self.assertIn(
                (cache_dir, "cache-like-inside-support", 35, "cache-like descendant"),
                details,
            )

    def test_write_csv_writes_headers_for_empty_rows(self):
        output = NonClosingStringIO()

        with mock.patch.object(Path, "mkdir"), \
                mock.patch.object(Path, "open", return_value=output):
            audit.write_csv(Path("/virtual/out/empty.csv"), [], ["first", "second"])

        output.seek(0)
        self.assertEqual(list(csv.reader(output)), [["first", "second"]])

    def test_main_writes_all_csv_outputs_when_no_rows(self):
        prefix = Path("/virtual/out/empty_audit")
        argv = ["mac_app_storage_audit_v2.py", "--csv-prefix", str(prefix)]
        write_calls = []

        def fake_write_csv(path, rows, fieldnames):
            write_calls.append((path, rows, fieldnames))

        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(audit, "find_apps", return_value=[]), \
                mock.patch.object(audit, "add_candidates"), \
                mock.patch.object(audit, "build_large_dir_rows", return_value=([], [])), \
                mock.patch.object(audit, "write_csv", fake_write_csv), \
                mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache()):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = audit.main()

        expected_paths = [
            prefix.with_name(prefix.name + "_by_app.csv"),
            prefix.with_name(prefix.name + "_matched_paths.csv"),
            prefix.with_name(prefix.name + "_large_library_dirs_raw.csv"),
            prefix.with_name(prefix.name + "_large_library_dirs_specific.csv"),
        ]

        self.assertEqual(rc, 0)
        self.assertEqual([call[0] for call in write_calls], expected_paths)
        self.assertEqual([call[1] for call in write_calls], [[], [], [], []])
        self.assertEqual(write_calls[0][2], audit.BY_APP_FIELDS)
        self.assertEqual(write_calls[1][2], audit.MATCHED_PATH_FIELDS)
        self.assertEqual(write_calls[2][2], audit.LARGE_DIR_FIELDS)
        self.assertEqual(write_calls[3][2], audit.LARGE_DIR_FIELDS)
        for path in expected_paths:
            self.assertIn(str(path), stdout.getvalue())

    def test_entry_matching_does_not_use_broad_substrings(self):
        entry = audit.DirIndexEntry(
            path=Path("/tmp/Xcode"),
            root=Path("/tmp"),
            rel_norm="xcode",
            leaf_norm="xcode",
            first2_norm="xcode",
            depth=1,
        )

        self.assertFalse(audit.entry_matches_app(entry, {"code"}))
        self.assertTrue(audit.entry_matches_app(entry, {"xcode"}))

    def test_find_apps_skips_nested_apps(self):
        root = Path("/virtual/Applications")
        outer = root / "Outer.app"
        nested = outer / "Nested.app"

        def fake_walk(path):
            self.assertEqual(Path(path), root)
            dirnames = ["Outer.app", "Utilities"]
            yield str(root), dirnames, []
            if "Outer.app" in dirnames:
                yield str(outer), ["Nested.app"], []
                yield str(nested), [], []

        with mock.patch.object(Path, "exists", lambda path: path == root or path == outer), \
                mock.patch.object(audit.os, "walk", fake_walk), \
                mock.patch.object(audit, "read_info_plist", return_value=("Outer", "com.example.outer", "OuterExec")), \
                mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache({outer: 12})):
            apps = audit.find_apps([root])

        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].name, "Outer")
        self.assertEqual(apps[0].bundle_id, "com.example.outer")
        self.assertEqual(apps[0].executable, "OuterExec")
        self.assertEqual(apps[0].size_kb, 12)

    def test_decode_legacy_host_db_path_accepts_unpadded_base64(self):
        encoded = "L1VzZXJzL21lL0Ryb3Bib3g"

        self.assertEqual(audit.decode_legacy_host_db_path(encoded), Path("/Users/me/Dropbox"))
        self.assertIsNone(audit.decode_legacy_host_db_path("not-a-path"))

    def test_add_dropbox_location_merges_sources_and_preserves_known_category(self):
        path = Path("/virtual/home/Dropbox")
        locations = {}

        with mock.patch.object(Path, "exists", lambda candidate: candidate == path):
            audit.add_dropbox_location(
                locations,
                path,
                "sync-root-local-files",
                "risk-one",
                "source-one",
                "note-one",
            )
            audit.add_dropbox_location(
                locations,
                path,
                "discovered-dropbox-path",
                "risk-two",
                "source-two",
                "note-two",
            )

        loc = locations[str(path)]
        self.assertEqual(loc.category, "sync-root-local-files")
        self.assertEqual(loc.cleanup_risk, "risk-one")
        self.assertEqual(loc.source, "source-one; source-two")
        self.assertEqual(loc.notes, "note-one; note-two")

    def test_dropbox_library_discovery_adds_file_provider_root_mount(self):
        home = Path("/virtual/home")
        with patched_library(home) as lib:
            group_containers = lib / "Group Containers"
            sync_container = group_containers / "TEAM.com.getdropbox.dropbox.sync"
            root_mount = sync_container / "root-mount"
            existing = {sync_container, root_mount}

            def fake_iterdir(path):
                if path == group_containers:
                    return [sync_container]
                return []

            with mock.patch.object(audit, "safe_iterdir", fake_iterdir), \
                    mock.patch.object(Path, "exists", lambda path: path in existing):
                locations = {}
                audit.add_dropbox_library_discovery(locations)

            self.assertEqual(locations[str(sync_container)].category, "container/group-container")
            self.assertEqual(locations[str(root_mount)].category, "file-provider-cache")

    def test_build_dropbox_location_rows_marks_nested_paths(self):
        root = Path("/virtual/home/Dropbox")
        cache = root / ".dropbox.cache"
        locations = {
            str(root): audit.DropboxLocation(root, "sync-root-local-files", "risk", "source"),
            str(cache): audit.DropboxLocation(cache, "legacy-sync-cache", "risk", "source"),
        }

        with mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache({root: 100, cache: 25})):
            rows = audit.build_dropbox_location_rows(locations)

        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path[str(root)]["nested_under"], "")
        self.assertEqual(by_path[str(cache)]["nested_under"], str(root))
        self.assertEqual(rows[0]["path"], str(root))

    def test_dropbox_only_main_skips_app_audit(self):
        argv = ["mac_app_storage_audit_v2.py", "--dropbox-only"]

        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(audit, "run_dropbox_scan", return_value=([], [])) as run_dropbox_scan, \
                mock.patch.object(audit, "find_apps") as find_apps, \
                mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache()):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = audit.main()

        self.assertEqual(rc, 0)
        run_dropbox_scan.assert_called_once()
        find_apps.assert_not_called()
        self.assertIn("Nothing was deleted.", stdout.getvalue())

    def test_run_dropbox_scan_writes_location_csvs_even_with_no_rows(self):
        args = SimpleNamespace(
            csv_prefix="/virtual/out/audit",
            dropbox_search_volumes=False,
            dropbox_deep_discovery=False,
            dropbox_top_children=40,
            dropbox_local_inventory=False,
            top=10,
        )
        write_calls = []

        def fake_write_csv(path, rows, fieldnames):
            write_calls.append((path, rows, fieldnames))

        with mock.patch.object(audit, "add_known_dropbox_paths"), \
                mock.patch.object(audit, "add_dropbox_sync_roots", return_value=[]), \
                mock.patch.object(audit, "add_dropbox_library_discovery"), \
                mock.patch.object(audit, "write_csv", fake_write_csv), \
                mock.patch.object(audit, "SIZE_CACHE", FakeSizeCache()):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                location_rows, child_rows = audit.run_dropbox_scan(args)

        self.assertEqual(location_rows, [])
        self.assertEqual(child_rows, [])
        self.assertEqual(
            [call[0] for call in write_calls],
            [
                Path("/virtual/out/audit_dropbox_locations.csv"),
                Path("/virtual/out/audit_dropbox_top_children.csv"),
            ],
        )
        self.assertEqual(write_calls[0][1], [])
        self.assertEqual(write_calls[0][2], audit.DROPBOX_LOCATION_FIELDS)
        self.assertEqual(write_calls[1][1], [])
        self.assertEqual(write_calls[1][2], audit.DROPBOX_TOP_CHILD_FIELDS)
        self.assertIn("Dropbox CSV written:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
