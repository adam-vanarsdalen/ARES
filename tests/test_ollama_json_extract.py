import unittest

from ollama_compat import extract_first_json_object


class TestJSONExtraction(unittest.TestCase):
    def test_extract_simple_object(self):
        self.assertEqual(extract_first_json_object('{"a": 1}'), '{"a": 1}')

    def test_extract_with_preamble_and_trailing(self):
        txt = "here you go:\n```json\n{\"a\": 1, \"b\": 2}\n```\nthanks"
        self.assertEqual(extract_first_json_object(txt), '{"a": 1, "b": 2}')

    def test_extract_ignores_braces_in_strings(self):
        txt = 'note {"a":"{not a brace}", "b": 2} tail'
        self.assertEqual(extract_first_json_object(txt), '{"a":"{not a brace}", "b": 2}')

    def test_no_object(self):
        self.assertEqual(extract_first_json_object("no json here"), "")

    def test_extract_array(self):
        txt = "note:\n[1,2,{\"a\":3}]\nend"
        self.assertEqual(extract_first_json_object(txt), '[1,2,{"a":3}]')

    def test_extracts_json_inside_think(self):
        txt = "<think>reasoning...</think>\n{\"a\": 1}\n"
        self.assertEqual(extract_first_json_object(txt), '{"a": 1}')


if __name__ == "__main__":
    unittest.main()
