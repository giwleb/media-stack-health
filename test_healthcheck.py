import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import healthcheck as h


class Tests(unittest.TestCase):
    def test_disk_healthy(self):
        self.assertEqual(h.disk_result(100*2**30, 50*2**30, 100, 100)[0], 'PASS')

    def test_disk_percent_warning(self):
        self.assertEqual(h.disk_result(100*2**30, 15*2**30, 100, 100)[0], 'WARN')

    def test_disk_critical(self):
        self.assertEqual(h.disk_result(100*2**30, 5*2**30, 100, 100)[0], 'FAIL')

    def test_disk_absolute_space(self):
        self.assertEqual(h.disk_result(3*2**30, 1.5*2**30, 100, 100)[0], 'FAIL')

    def test_inode_exhaustion(self):
        self.assertEqual(h.disk_result(100*2**30, 90*2**30, 1, 100)[0], 'FAIL')

    def test_transient_failure_debounced(self):
        row = dict(id='service', level='FAIL', detail='down')
        counts, active = h.new_issues([row], {})
        self.assertFalse(active)
        _, active = h.new_issues([row], counts)
        self.assertEqual(active, {'service':'FAIL'})

    def test_security_failure_immediate(self):
        _, active = h.new_issues([dict(id='vpn', level='FAIL', urgent=True)], {})
        self.assertIn('vpn', active)

    def test_recovery_resets_consecutive_count(self):
        self.assertEqual(h.new_issues([dict(id='x', level='PASS')], {'x':5}), ({}, {}))

    def test_volatile_detail_does_not_repeat_alert(self):
        a = h.new_issues([dict(id='disk', level='WARN', detail='81%')], {'disk':2})[1]
        b = h.new_issues([dict(id='disk', level='WARN', detail='82%')], {'disk':3})[1]
        self.assertEqual(h.signature(a), h.signature(b))
        self.assertNotEqual(h.signature(a), h.signature({}))

    def test_command_error_redacts_arguments_and_output(self):
        with self.assertRaises(RuntimeError) as e:
            h.command(['sh','-c','echo SUPER_SECRET >&2; exit 1'])
        self.assertNotIn('SECRET', str(e.exception))

    def test_namespace_mismatch_immediate(self):
        c = dict(project_dir='.', vpn_container='vpn_gateway', vpn_clients=['qbittorrent'], vpn_interface='tun0', ip_url='http://unused')
        m = h.Monitor(c, {}, False)
        def dex(name,*args,**kwargs):
            if args[0] == '/gluetun-entrypoint': return ''
            if args[0] == 'readlink': return 'net:[1]' if name == 'vpn_gateway' else 'net:[2]'
            if args[0] == 'cat': return '203.0.113.1'
            raise RuntimeError('not available')
        with patch.object(m,'dex',side_effect=dex), patch.object(h.urllib.request,'urlopen',side_effect=OSError):
            m.vpn_checks()
        row = next(x for x in m.rows if x['id']=='vpn:namespace:qbittorrent')
        self.assertEqual(row['level'],'FAIL')
        self.assertTrue(row['urgent'])

    def test_qbit_port_mismatch(self):
        c = dict(project_dir='.', qbit_container='qbittorrent', vpn_container='vpn_gateway',vpn_interface='tun0')
        m = h.Monitor(c, {}, False)
        def dex(name,*args,**kwargs):
            if args[0]=='cat': return '48725'
            url=args[-1]
            if url.endswith('preferences'): return json.dumps(dict(current_network_interface='tun0',listen_port=27493,random_port=False,upnp=False))
            if url.endswith('transfer/info'): return '{"connection_status":"connected"}'
            return '[]'
        with patch.object(m,'dex',side_effect=dex): m.qbit_checks()
        self.assertEqual(next(r for r in m.rows if r['id']=='qbit:port')['level'],'FAIL')

    def test_atomic_state_private(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'state.json'
            h.atomic_json(p, {'value':1})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(p.read_text()), {'value':1})

    def test_smtp_disabled_does_not_send(self):
        with patch.object(h.smtplib,'SMTP') as smtp:
            with self.assertRaises(RuntimeError): h.send_email({'enabled':False},'body','subject')
            smtp.assert_not_called()

    def test_dry_run_never_notifies_or_changes_state(self):
        with tempfile.TemporaryDirectory() as d:
            cfg=dict(project_dir=d,state_dir=d+'/state')
            path=Path(d)/'config.json'
            path.write_text(json.dumps(cfg)); path.chmod(0o600)
            with patch.object(h.Monitor,'run',return_value=[dict(id='ok',level='PASS',detail='OK')]), patch.object(h,'http_json') as http, patch.object(h,'send_email') as mail, patch.object(h.sys,'argv',['healthcheck','--config',str(path),'--dry-run']), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(),0)
                http.assert_not_called(); mail.assert_not_called()
            self.assertFalse((Path(d)/'state/state.json').exists())

    def test_delivery_failure_is_retried(self):
        with tempfile.TemporaryDirectory() as d:
            cfg=dict(project_dir=d,state_dir=d+'/state',ha_webhook_url='http://unused',failure_checks=1)
            path=Path(d)/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
            rows=[dict(id='x',level='FAIL',detail='down')]
            with patch.object(h.Monitor,'run',side_effect=lambda:[dict(x) for x in rows]), patch.object(h,'http_json',side_effect=OSError) as http, patch.object(h.sys,'argv',['h','--config',str(path)]), contextlib.redirect_stderr(io.StringIO()):
                h.main();h.main()
                self.assertTrue(all(call.args[1]['notify'] for call in http.call_args_list))


if __name__=='__main__': unittest.main()
