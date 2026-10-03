import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from model_client import Client, ModelIssue


class GroundingChecks(unittest.TestCase):
    def test_model_cannot_supply_new_prose(self):
        request = {'source': 'Project Cedar\nOwner Maya\nDue Friday', 'mode': 'summary', 'name': 'note.txt'}
        with patch.object(Client, 'request', return_value={'line_ids': [0, 1, 2]}):
            text, receipt = Client(Path('.')).generate(request)
        self.assertEqual(receipt['selected_source_lines'], request['source'].splitlines())
        self.assertIn(b'Owner Maya', text)
        self.assertNotIn(b'Monday', text)

    def test_invented_indexes_prose_booleans_duplicates_refused(self):
        for reply in ({'line_ids': [99]}, {'text': 'Invented answer'}, {'line_ids': [True]},
                      {'line_ids': [0, 0]}, {'line_ids': [['x']]}, {'line_ids': []}):
            with self.subTest(reply=reply), patch.object(Client, 'request', return_value=reply):
                with self.assertRaises(ModelIssue):
                    Client(Path('.')).generate({'source': 'Fact A\nFact B', 'mode': 'summary', 'name': 'note.txt'})

    def test_plan_excludes_buy_send_and_external_actions(self):
        source = '[ ] Buy equipment\n[ ] Send email\n[ ] Open browser\n[ ] Read approved note\n[ ] Draft local checklist'
        with patch.object(Client, 'request', return_value={'line_ids': [0, 1]}):
            text, receipt = Client(Path('.')).generate({'source': source, 'mode': 'plan', 'name': 'todo.txt'})
        self.assertEqual(receipt['selected_source_lines'], ['[ ] Read approved note', '[ ] Draft local checklist'])
        self.assertNotIn(b'Buy', text)

    def test_no_external_loopback_ports_dns_or_subprocess(self):
        script = '''
import sys, socket, subprocess
from model_client import local_model_hook, ModelIssue
sys.addaudithook(local_model_hook)
for f in (lambda: socket.getaddrinfo('example.invalid',443),
          lambda: socket.create_connection(('127.0.0.1',18184)),
          lambda: socket.create_connection(('192.0.2.1',80)),
          lambda: socket.socket(socket.AF_INET,socket.SOCK_DGRAM),
          lambda: subprocess.Popen([sys.executable,'-c','pass'])):
 try: f()
 except ModelIssue: continue
 raise SystemExit(1)
'''
        result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).parent,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_mode_fields_and_oversize_refused(self):
        for request in ({'source': 'A', 'mode': 'email', 'name': 'a.txt'},
                        {'source': 'A', 'mode': 'summary', 'name': 'a.txt', 'url': 'x'},
                        {'source': 'A' * 8001, 'mode': 'summary', 'name': 'a.txt'}):
            with self.assertRaises(ModelIssue):
                Client(Path('.')).generate(request)


if __name__ == '__main__':
    unittest.main()
