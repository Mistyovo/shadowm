"""Pure-logic tests: no windows, no Qt event loop needed."""

import ast
import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import capture_hider
import taskbar_hider
import window_opacity
from capture_hider import k32
from paths import migrate_legacy_files, state_dir
from session_state import SessionState, boot_marker
from ui import TASKBAR_SUFFIX, _strip_taskbar_suffix
import main as main_module
import ui


class SuffixTests(unittest.TestCase):
    def test_strips_suffix(self):
        self.assertEqual(
            _strip_taskbar_suffix("Notepad" + TASKBAR_SUFFIX), "Notepad"
        )

    def test_plain_text_untouched(self):
        self.assertEqual(_strip_taskbar_suffix("Notepad"), "Notepad")

    def test_suffix_only(self):
        self.assertEqual(_strip_taskbar_suffix(TASKBAR_SUFFIX), "")


class BootMarkerTests(unittest.TestCase):
    def test_stable_within_one_boot(self):
        self.assertLess(abs(boot_marker() - boot_marker()), 5000)


class SessionStateTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_roundtrip_and_clear(self):
        state = SessionState(self.path)
        self.assertTrue(state.is_empty())
        state.note_capture_hidden(100, 42, "C:/x/app.exe")
        state.note_taskbar_hidden(101, 42, 0x80)
        state.note_opacity(102, 42, True, None)
        state.save()

        reloaded = SessionState(self.path)
        self.assertEqual(reloaded.capture_items(), [(100, {"pid": 42, "exe": "C:/x/app.exe"})])
        self.assertEqual(reloaded.taskbar_items(), [(101, {"pid": 42, "exstyle": 0x80})])
        self.assertEqual(
            reloaded.opacity_items(),
            [(102, {"pid": 42, "added_layered": True, "original_alpha": None})],
        )
        self.assertFalse(reloaded.is_empty())

        reloaded.clear_capture(100)
        reloaded.clear_taskbar(101)
        reloaded.clear_opacity(102)
        self.assertTrue(reloaded.is_empty())

    def test_stale_boot_discarded(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(
                {"boot": 0, "capture": {"7": {"pid": 1, "exe": "x"}}},
                f,
            )
        state = SessionState(self.path)
        self.assertTrue(state.is_empty())

    def test_corrupt_file_discarded(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{not json")
        state = SessionState(self.path)
        self.assertTrue(state.is_empty())

    def test_delete_removes_file(self):
        state = SessionState(self.path)
        state.note_capture_hidden(1, 1, "a")
        self.assertTrue(os.path.exists(self.path))
        state.delete()
        self.assertFalse(os.path.exists(self.path))


class StaticApiUsageTests(unittest.TestCase):
    """ui.py calls hider classes by name; a typo'd attribute only blows up
    at runtime - and PyQt5 then aborts the whole process. Catch the class
    of bug statically (e.g. WindowCaptureHider.window_exists never existed
    as a classmethod and crashed every run ~1.5s in)."""

    CLASSES = {
        "WindowCaptureHider": capture_hider.WindowCaptureHider,
        "TaskbarHider": taskbar_hider.TaskbarHider,
        "WindowOpacity": window_opacity.WindowOpacity,
    }

    def test_ui_calls_only_existing_attributes(self):
        tree = ast.parse(inspect.getsource(ui))
        pairs = {
            (node.func.value.id, node.func.attr)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.CLASSES
        }
        self.assertTrue(pairs)  # the scan itself must find something
        for cls_name, attr in sorted(pairs):
            self.assertTrue(
                hasattr(self.CLASSES[cls_name], attr),
                f"ui.py calls {cls_name}.{attr} which does not exist",
            )


class SingleInstanceTests(unittest.TestCase):
    def test_second_acquire_fails(self):
        name = "ShadowM.unittest." + uuid.uuid4().hex
        first = main_module.acquire_single_instance_mutex(name)
        self.assertIsNotNone(first)
        self.assertIsNone(main_module.acquire_single_instance_mutex(name))


class StateDirTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _set_appdata(self):
        old = os.environ.get("APPDATA")
        os.environ["APPDATA"] = self.tmp

        def restore():
            if old is None:
                os.environ.pop("APPDATA", None)
            else:
                os.environ["APPDATA"] = old

        self.addCleanup(restore)

    def test_state_dir_under_appdata(self):
        self._set_appdata()
        self.assertEqual(state_dir(), os.path.join(self.tmp, "ShadowM"))
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "ShadowM")))


class LegacyStateMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.legacy = os.path.join(self.tmp, "legacy")
        self.target = os.path.join(self.tmp, "state")
        os.makedirs(self.legacy)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_legacy(self):
        src = os.path.join(self.legacy, "remembered_hidden.json")
        with open(src, "w", encoding="utf-8") as f:
            json.dump({"C:/x/a.exe": {"title": "A", "ts": 1}}, f)
        return src

    def test_moves_file_into_target(self):
        src = self._write_legacy()
        moved = migrate_legacy_files(
            target_dir=self.target, legacy_dirs=[self.legacy]
        )
        self.assertEqual(moved, ["remembered_hidden.json"])
        self.assertFalse(os.path.exists(src))
        with open(
            os.path.join(self.target, "remembered_hidden.json"),
            encoding="utf-8",
        ) as f:
            self.assertIn("a.exe", f.read())

    def test_existing_target_not_overwritten(self):
        self._write_legacy()
        os.makedirs(self.target)
        with open(
            os.path.join(self.target, "remembered_hidden.json"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write("{}")
        moved = migrate_legacy_files(
            target_dir=self.target, legacy_dirs=[self.legacy]
        )
        self.assertEqual(moved, [])
        # the legacy copy stays for manual recovery
        self.assertTrue(os.path.exists(os.path.join(self.legacy, "remembered_hidden.json")))

    def test_no_legacy_file_is_noop(self):
        moved = migrate_legacy_files(
            target_dir=self.target, legacy_dirs=[self.legacy]
        )
        self.assertEqual(moved, [])


if __name__ == "__main__":
    unittest.main()
