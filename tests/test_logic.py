"""Pure-logic tests: no windows, no Qt event loop needed."""

import json
import os
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture_hider import k32
from session_state import SessionState, boot_marker
from ui import TASKBAR_SUFFIX, _strip_taskbar_suffix
import main as main_module


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


class SingleInstanceTests(unittest.TestCase):
    def test_second_acquire_fails(self):
        name = "ShadowM.unittest." + uuid.uuid4().hex
        first = main_module.acquire_single_instance_mutex(name)
        self.assertIsNotNone(first)
        self.assertIsNone(main_module.acquire_single_instance_mutex(name))


if __name__ == "__main__":
    unittest.main()
