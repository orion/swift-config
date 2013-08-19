# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Tests for swift.common.wsgi """

from __future__ import with_statement
import errno
import logging
import mimetools
import socket
import unittest
import os
import re
import pickle
from textwrap import dedent
from gzip import GzipFile
from StringIO import StringIO
from collections import defaultdict
from contextlib import contextmanager, closing
from urllib import quote
from tempfile import mkstemp

from eventlet import listen

import swift
from swift.common.swob import Request
from swift.common import wsgi, utils, ring

from test.unit import temptree

from mock import patch


def _fake_rings(tmpdir):
    with closing(GzipFile(os.path.join(tmpdir, 'account.ring.gz'), 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': 6012},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': 6022}], 30),
                    f)
    with closing(GzipFile(os.path.join(tmpdir, 'container.ring.gz'), 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': 6011},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': 6021}], 30),
                    f)
    with closing(GzipFile(os.path.join(tmpdir, 'object.ring.gz'), 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': 6010},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': 6020}], 30),
                    f)


class TestWSGI(unittest.TestCase):
    """ Tests for swift.common.wsgi """

    def setUp(self):
        utils.HASH_PATH_PREFIX = 'startcap'
        self._orig_parsetype = mimetools.Message.parsetype

    def tearDown(self):
        mimetools.Message.parsetype = self._orig_parsetype

    def test_monkey_patch_mimetools(self):
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).type, 'text/plain')
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).plisttext, '')
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).maintype, 'text')
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).subtype, 'plain')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).type, 'text/html')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).plisttext,
                          '; charset=ISO-8859-4')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).maintype, 'text')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).subtype, 'html')

        wsgi.monkey_patch_mimetools()
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).type, None)
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).plisttext, '')
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).maintype, None)
        sio = StringIO('blah')
        self.assertEquals(mimetools.Message(sio).subtype, None)
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).type, 'text/html')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).plisttext,
                          '; charset=ISO-8859-4')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).maintype, 'text')
        sio = StringIO('Content-Type: text/html; charset=ISO-8859-4')
        self.assertEquals(mimetools.Message(sio).subtype, 'html')

    def test_init_request_processor(self):
        config = """
        [DEFAULT]
        swift_dir = TEMPDIR

        [pipeline:main]
        pipeline = catch_errors proxy-server

        [app:proxy-server]
        use = egg:swift#proxy
        conn_timeout = 0.2

        [filter:catch_errors]
        use = egg:swift#catch_errors
        """
        contents = dedent(config)
        with temptree(['proxy-server.conf']) as t:
            conf_file = os.path.join(t, 'proxy-server.conf')
            with open(conf_file, 'w') as f:
                f.write(contents.replace('TEMPDIR', t))
            _fake_rings(t)
            app, conf, logger, log_name = wsgi.init_request_processor(
                conf_file, 'proxy-server')
        # verify pipeline is catch_errors -> proxy-server
        expected = swift.common.middleware.catch_errors.CatchErrorMiddleware
        self.assert_(isinstance(app, expected))
        self.assert_(isinstance(app.app, swift.proxy.server.Application))
        # config settings applied to app instance
        self.assertEquals(0.2, app.app.conn_timeout)
        # appconfig returns values from 'proxy-server' section
        expected = {
            '__file__': conf_file,
            'here': os.path.dirname(conf_file),
            'conn_timeout': '0.2',
            'swift_dir': t,
        }
        self.assertEquals(expected, conf)
        # logger works
        logger.info('testing')
        self.assertEquals('proxy-server', log_name)

    def test_init_request_processor_from_conf_dir(self):
        config_dir = {
            'proxy-server.conf.d/pipeline.conf': """
            [pipeline:main]
            pipeline = catch_errors proxy-server
            """,
            'proxy-server.conf.d/app.conf': """
            [app:proxy-server]
            use = egg:swift#proxy
            conn_timeout = 0.2
            """,
            'proxy-server.conf.d/catch-errors.conf': """
            [filter:catch_errors]
            use = egg:swift#catch_errors
            """
        }
        # strip indent from test config contents
        config_dir = dict((f, dedent(c)) for (f, c) in config_dir.items())
        with temptree(*zip(*config_dir.items())) as conf_root:
            conf_dir = os.path.join(conf_root, 'proxy-server.conf.d')
            with open(os.path.join(conf_dir, 'swift.conf'), 'w') as f:
                f.write('[DEFAULT]\nswift_dir = %s' % conf_root)
            _fake_rings(conf_root)
            app, conf, logger, log_name = wsgi.init_request_processor(
                conf_dir, 'proxy-server')
        # verify pipeline is catch_errors -> proxy-server
        expected = swift.common.middleware.catch_errors.CatchErrorMiddleware
        self.assert_(isinstance(app, expected))
        self.assert_(isinstance(app.app, swift.proxy.server.Application))
        # config settings applied to app instance
        self.assertEquals(0.2, app.app.conn_timeout)
        # appconfig returns values from 'proxy-server' section
        expected = {
            '__file__': conf_dir,
            'here': conf_dir,
            'conn_timeout': '0.2',
            'swift_dir': conf_root,
        }
        self.assertEquals(expected, conf)
        # logger works
        logger.info('testing')
        self.assertEquals('proxy-server', log_name)

    def test_init_request_processor_with_dynamic_pipeline(self):
        config_dir = {
            'proxy-server.conf.d/pipeline.conf': """
            [pipeline:main]
            pipeline = tempauth proxy-server
            """,
            'proxy-server.conf.d/app.conf': """
            [app:proxy-server]
            use = egg:swift#proxy
            """,
            'proxy-server.conf.d/catch-errors.conf': """
            [filter:catch_errors]
            use = egg:swift#catch_errors
            before = #all, healthcheck 
            """,
            'proxy-server.conf.d/others.conf': """
            [filter:tempauth]
            use = egg:swift#tempauth

            [filter:keystone]
            paste.filter_factory = keystone.middleware.swift_auth:filter_factory
            before = tempauth, proxy-server

            [filter:authtoken]
            paste.filter_factory = keystone.middleware.auth_token:filter_factory
            before = keystone, tempauth, proxy-server 

            [filter:healthcheck]
            use = egg:swift#healthcheck
            before = #all, catch_errors 
            """,
        }

        # strip indent from test config contents
        config_dir = dict((f, dedent(c)) for (f, c) in config_dir.items())
        with temptree(*zip(*config_dir.items())) as conf_root:
            conf_dir = os.path.join(conf_root, 'proxy-server.conf.d')
            with open(os.path.join(conf_dir, 'swift.conf'), 'w') as f:
                f.write('[DEFAULT]\nswift_dir = %s' % conf_root)
            _fake_rings(conf_root)
            app, conf, logger, log_name = wsgi.init_request_processor(
                conf_dir, 'proxy-server')

        # verify pipeline 
        def get_pipeline(app):
            yield app
            while hasattr(app, 'app'):
                app = app.app
                yield app

        def get_pipeline_class_names(app):
            for ware in get_pipeline(app):
                yield ware.__class__.__name__

        expected_classnames = [
            'CatchErrorsMiddleware', 
            'HealthCheckMiddleware',
            'AuthTokenMiddleware',
            'KeystoneMiddleware',
            'TempAuth',
            'Application']

        pipeline_classnames = list(get_pipeline_class_names(app))
        self.assertEquals(expected_classnames, pipeline_classnames)

    def test_get_socket(self):
        # stubs
        conf = {}
        ssl_conf = {
            'cert_file': '',
            'key_file': '',
        }

        # mocks
        class MockSocket():
            def __init__(self):
                self.opts = defaultdict(dict)

            def setsockopt(self, level, optname, value):
                self.opts[level][optname] = value

        def mock_listen(*args, **kwargs):
            return MockSocket()

        class MockSsl():
            def __init__(self):
                self.wrap_socket_called = []

            def wrap_socket(self, sock, **kwargs):
                self.wrap_socket_called.append(kwargs)
                return sock

        # patch
        old_listen = wsgi.listen
        old_ssl = wsgi.ssl
        try:
            wsgi.listen = mock_listen
            wsgi.ssl = MockSsl()
            # test
            sock = wsgi.get_socket(conf)
            # assert
            self.assert_(isinstance(sock, MockSocket))
            expected_socket_opts = {
                socket.SOL_SOCKET: {
                    socket.SO_REUSEADDR: 1,
                    socket.SO_KEEPALIVE: 1,
                },
            }
            if hasattr(socket, 'TCP_KEEPIDLE'):
                expected_socket_opts[socket.IPPROTO_TCP] = {
                    socket.TCP_KEEPIDLE: 600,
                }
            self.assertEquals(sock.opts, expected_socket_opts)
            # test ssl
            sock = wsgi.get_socket(ssl_conf)
            expected_kwargs = {
                'certfile': '',
                'keyfile': '',
            }
            self.assertEquals(wsgi.ssl.wrap_socket_called, [expected_kwargs])
        finally:
            wsgi.listen = old_listen
            wsgi.ssl = old_ssl

    def test_address_in_use(self):
        # stubs
        conf = {}

        # mocks
        def mock_listen(*args, **kwargs):
            raise socket.error(errno.EADDRINUSE)

        def value_error_listen(*args, **kwargs):
            raise ValueError('fake')

        def mock_sleep(*args):
            pass

        class MockTime():
            """Fast clock advances 10 seconds after every call to time
            """
            def __init__(self):
                self.current_time = old_time.time()

            def time(self, *args, **kwargs):
                rv = self.current_time
                # advance for next call
                self.current_time += 10
                return rv

        old_listen = wsgi.listen
        old_sleep = wsgi.sleep
        old_time = wsgi.time
        try:
            wsgi.listen = mock_listen
            wsgi.sleep = mock_sleep
            wsgi.time = MockTime()
            # test error
            self.assertRaises(Exception, wsgi.get_socket, conf)
            # different error
            wsgi.listen = value_error_listen
            self.assertRaises(ValueError, wsgi.get_socket, conf)
        finally:
            wsgi.listen = old_listen
            wsgi.sleep = old_sleep
            wsgi.time = old_time

    def test_run_server(self):
        config = """
        [DEFAULT]
        eventlet_debug = yes
        client_timeout = 30
        max_clients = 1000
        swift_dir = TEMPDIR

        [pipeline:main]
        pipeline = proxy-server

        [app:proxy-server]
        use = egg:swift#proxy
        # while "set" values normally override default
        set client_timeout = 20
        # this section is not in conf during run_server
        set max_clients = 10
        """

        contents = dedent(config)
        with temptree(['proxy-server.conf']) as t:
            conf_file = os.path.join(t, 'proxy-server.conf')
            with open(conf_file, 'w') as f:
                f.write(contents.replace('TEMPDIR', t))
            _fake_rings(t)
            with patch('swift.common.wsgi.wsgi') as _wsgi:
                with patch('swift.common.wsgi.eventlet') as _eventlet:
                    conf = wsgi.appconfig(conf_file)
                    logger = logging.getLogger('test')
                    sock = listen(('localhost', 0))
                    wsgi.run_server(conf, logger, sock)
        self.assertEquals('HTTP/1.0',
                          _wsgi.HttpProtocol.default_request_version)
        self.assertEquals(30, _wsgi.WRITE_TIMEOUT)
        _eventlet.hubs.use_hub.assert_called_with(utils.get_hub())
        _eventlet.patcher.monkey_patch.assert_called_with(all=False,
                                                          socket=True)
        _eventlet.debug.hub_exceptions.assert_called_with(True)
        _wsgi.server.assert_called()
        args, kwargs = _wsgi.server.call_args
        server_sock, server_app, server_logger = args
        self.assertEquals(sock, server_sock)
        self.assert_(isinstance(server_app, swift.proxy.server.Application))
        self.assertEquals(20, server_app.client_timeout)
        self.assert_(isinstance(server_logger, wsgi.NullLogger))
        self.assert_('custom_pool' in kwargs)
        self.assertEquals(1000, kwargs['custom_pool'].size)

    def test_run_server_conf_dir(self):
        config_dir = {
            'proxy-server.conf.d/pipeline.conf': """
            [pipeline:main]
            pipeline = proxy-server
            """,
            'proxy-server.conf.d/app.conf': """
            [app:proxy-server]
            use = egg:swift#proxy
            """,
            'proxy-server.conf.d/default.conf': """
            [DEFAULT]
            eventlet_debug = yes
            client_timeout = 30
            """
        }
        # strip indent from test config contents
        config_dir = dict((f, dedent(c)) for (f, c) in config_dir.items())
        with temptree(*zip(*config_dir.items())) as conf_root:
            conf_dir = os.path.join(conf_root, 'proxy-server.conf.d')
            with open(os.path.join(conf_dir, 'swift.conf'), 'w') as f:
                f.write('[DEFAULT]\nswift_dir = %s' % conf_root)
            _fake_rings(conf_root)
            with patch('swift.common.wsgi.wsgi') as _wsgi:
                with patch('swift.common.wsgi.eventlet') as _eventlet:
                    with patch.dict('os.environ', {'TZ': ''}):
                        conf = wsgi.appconfig(conf_dir)
                        logger = logging.getLogger('test')
                        sock = listen(('localhost', 0))
                        wsgi.run_server(conf, logger, sock)
                        self.assert_(os.environ['TZ'] is not '')

        self.assertEquals('HTTP/1.0',
                          _wsgi.HttpProtocol.default_request_version)
        self.assertEquals(30, _wsgi.WRITE_TIMEOUT)
        _eventlet.hubs.use_hub.assert_called_with(utils.get_hub())
        _eventlet.patcher.monkey_patch.assert_called_with(all=False,
                                                          socket=True)
        _eventlet.debug.hub_exceptions.assert_called_with(True)
        _wsgi.server.assert_called()
        args, kwargs = _wsgi.server.call_args
        server_sock, server_app, server_logger = args
        self.assertEquals(sock, server_sock)
        self.assert_(isinstance(server_app, swift.proxy.server.Application))
        self.assert_(isinstance(server_logger, wsgi.NullLogger))
        self.assert_('custom_pool' in kwargs)

    def test_appconfig_dir_ignores_hidden_files(self):
        config_dir = {
            'server.conf.d/01.conf': """
            [app:main]
            use = egg:swift#proxy
            port = 8080
            """,
            'server.conf.d/.01.conf.swp': """
            [app:main]
            use = egg:swift#proxy
            port = 8081
            """,
        }
        # strip indent from test config contents
        config_dir = dict((f, dedent(c)) for (f, c) in config_dir.items())
        with temptree(*zip(*config_dir.items())) as path:
            conf_dir = os.path.join(path, 'server.conf.d')
            conf = wsgi.appconfig(conf_dir)
        expected = {
            '__file__': os.path.join(path, 'server.conf.d'),
            'here': os.path.join(path, 'server.conf.d'),
            'port': '8080',
        }
        self.assertEquals(conf, expected)

    def test_pre_auth_wsgi_input(self):
        oldenv = {}
        newenv = wsgi.make_pre_authed_env(oldenv)
        self.assertTrue('wsgi.input' in newenv)
        self.assertEquals(newenv['wsgi.input'].read(), '')

        oldenv = {'wsgi.input': StringIO('original wsgi.input')}
        newenv = wsgi.make_pre_authed_env(oldenv)
        self.assertTrue('wsgi.input' in newenv)
        self.assertEquals(newenv['wsgi.input'].read(), '')

        oldenv = {'swift.source': 'UT'}
        newenv = wsgi.make_pre_authed_env(oldenv)
        self.assertEquals(newenv['swift.source'], 'UT')

        oldenv = {'swift.source': 'UT'}
        newenv = wsgi.make_pre_authed_env(oldenv, swift_source='SA')
        self.assertEquals(newenv['swift.source'], 'SA')

    def test_pre_auth_req(self):
        class FakeReq(object):
            @classmethod
            def fake_blank(cls, path, environ={}, body='', headers={}):
                self.assertEquals(environ['swift.authorize']('test'), None)
                self.assertFalse('HTTP_X_TRANS_ID' in environ)
        was_blank = Request.blank
        Request.blank = FakeReq.fake_blank
        wsgi.make_pre_authed_request({'HTTP_X_TRANS_ID': '1234'},
                                     'PUT', '/', body='tester', headers={})
        wsgi.make_pre_authed_request({'HTTP_X_TRANS_ID': '1234'},
                                     'PUT', '/', headers={})
        Request.blank = was_blank

    def test_pre_auth_req_with_quoted_path(self):
        r = wsgi.make_pre_authed_request(
            {'HTTP_X_TRANS_ID': '1234'}, 'PUT', path=quote('/a space'),
            body='tester', headers={})
        self.assertEquals(r.path, quote('/a space'))

    def test_pre_auth_req_drops_query(self):
        r = wsgi.make_pre_authed_request(
            {'QUERY_STRING': 'original'}, 'GET', 'path')
        self.assertEquals(r.query_string, 'original')
        r = wsgi.make_pre_authed_request(
            {'QUERY_STRING': 'original'}, 'GET', 'path?replacement')
        self.assertEquals(r.query_string, 'replacement')
        r = wsgi.make_pre_authed_request(
            {'QUERY_STRING': 'original'}, 'GET', 'path?')
        self.assertEquals(r.query_string, '')

    def test_pre_auth_req_with_body(self):
        r = wsgi.make_pre_authed_request(
            {'QUERY_STRING': 'original'}, 'GET', 'path', 'the body')
        self.assertEquals(r.body, 'the body')

    def test_pre_auth_creates_script_name(self):
        e = wsgi.make_pre_authed_env({})
        self.assertTrue('SCRIPT_NAME' in e)

    def test_pre_auth_copies_script_name(self):
        e = wsgi.make_pre_authed_env({'SCRIPT_NAME': '/script_name'})
        self.assertEquals(e['SCRIPT_NAME'], '/script_name')

    def test_pre_auth_copies_script_name_unless_path_overridden(self):
        e = wsgi.make_pre_authed_env({'SCRIPT_NAME': '/script_name'},
                                     path='/override')
        self.assertEquals(e['SCRIPT_NAME'], '')
        self.assertEquals(e['PATH_INFO'], '/override')

    def test_pre_auth_req_swift_source(self):
        r = wsgi.make_pre_authed_request(
            {'QUERY_STRING': 'original'}, 'GET', 'path', 'the body',
            swift_source='UT')
        self.assertEquals(r.body, 'the body')
        self.assertEquals(r.environ['swift.source'], 'UT')

    def test_pre_auth_req_with_empty_env_no_path(self):
        r = wsgi.make_pre_authed_request(
            {}, 'GET')
        self.assertEquals(r.path, quote(''))
        self.assertTrue('SCRIPT_NAME' in r.environ)
        self.assertTrue('PATH_INFO' in r.environ)

    def test_pre_auth_req_with_env_path(self):
        r = wsgi.make_pre_authed_request(
            {'PATH_INFO': '/unquoted path with %20'}, 'GET')
        self.assertEquals(r.path, quote('/unquoted path with %20'))
        self.assertEquals(r.environ['SCRIPT_NAME'], '')

    def test_pre_auth_req_with_env_script(self):
        r = wsgi.make_pre_authed_request({'SCRIPT_NAME': '/hello'}, 'GET')
        self.assertEquals(r.path, quote('/hello'))

    def test_pre_auth_req_with_env_path_and_script(self):
        env = {'PATH_INFO': '/unquoted path with %20',
               'SCRIPT_NAME': '/script'}
        r = wsgi.make_pre_authed_request(env, 'GET')
        expected_path = quote(env['SCRIPT_NAME'] + env['PATH_INFO'])
        self.assertEquals(r.path, expected_path)
        env = {'PATH_INFO': '', 'SCRIPT_NAME': '/script'}
        r = wsgi.make_pre_authed_request(env, 'GET')
        self.assertEquals(r.path, '/script')
        env = {'PATH_INFO': '/path', 'SCRIPT_NAME': ''}
        r = wsgi.make_pre_authed_request(env, 'GET')
        self.assertEquals(r.path, '/path')
        env = {'PATH_INFO': '', 'SCRIPT_NAME': ''}
        r = wsgi.make_pre_authed_request(env, 'GET')
        self.assertEquals(r.path, '')

    def test_pre_auth_req_path_overrides_env(self):
        env = {'PATH_INFO': '/path', 'SCRIPT_NAME': '/script'}
        r = wsgi.make_pre_authed_request(env, 'GET', '/override')
        self.assertEquals(r.path, '/override')
        self.assertEquals(r.environ['SCRIPT_NAME'], '')
        self.assertEquals(r.environ['PATH_INFO'], '/override')

class TestWSGIContext(unittest.TestCase):

    def test_app_call(self):
        statuses = ['200 Ok', '404 Not Found']

        def app(env, start_response):
            start_response(statuses.pop(0), [('Content-Length', '3')])
            yield 'Ok\n'

        wc = wsgi.WSGIContext(app)
        r = Request.blank('/')
        it = wc._app_call(r.environ)
        self.assertEquals(wc._response_status, '200 Ok')
        self.assertEquals(''.join(it), 'Ok\n')
        r = Request.blank('/')
        it = wc._app_call(r.environ)
        self.assertEquals(wc._response_status, '404 Not Found')
        self.assertEquals(''.join(it), 'Ok\n')

@contextmanager
def temp_config(contents):
    fd, fn = mkstemp()
    try:
        fh = os.fdopen(fd, "w")
        fh.write(contents)
        fh.close()
        loader = wsgi.NamedConfigLoader(fn)
        yield loader.parser
    except Exception as e:
        yield e
    finally:
        os.unlink(fn)

from pprint import pprint
class TestConfigParsing(unittest.TestCase):
    def setUp(self):
        self.basic_config = dedent("""
            [pipeline:main]
            pipeline = catch_errors proxy-server
            dynamic = True

            [app:proxy-server]
            use = egg:swift#proxy
            conn_timeout = 0.2

            [filter:catch_errors]
            use = egg:swift#catch_errors
            """)

    def to_config(self, config_data, pipeline='main'):
        config = '' 
        for entry in config_data:
            config += '[filter:%s]\n' % entry[0]
            config += 'pipeline = %s\n' % pipeline
            for attrs in entry[1]:
                config += '%s = %s\n' % tuple(attrs)
        config += '\n'
        return config

    def append_config(self, config_lines):
        return "%s\n%s" % (self.basic_config, config_lines)

    # TODO: revert this to the text-based system
    def test_basic_interpolation(self):
        added_config = [
            ('attheend', (('after', 'between'),)),
            ('between', (('before', 'proxy-server'), 
                         ('after', 'catch_errors'))),
            ('atthestart', (('before', 'catch_errors'),))]
        config_text = self.append_config(self.to_config(added_config))

        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:main', 'pipeline')
            expected = 'atthestart catch_errors between attheend proxy-server'
            self.assertEquals(expected, pipeline)

    def test_provides(self):
        config_text = dedent(self.basic_config) + dedent("""
            [filter:kerberos]
            pipeline = main
            provides = authentication
            before = proxy-server provides:authorization
            after = catch_errors
            
            [filter:ldap]
            pipeline = main
            provides = authorization
            before = proxy-server
            after = provides:authentication catch_errors

            [filter:coffee]
            pipeline = main
            provides = java
            before = provides:authentication provides:authorization 
            after = catch_errors
            """)
        
        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:main', 'pipeline')
            expected = 'catch_errors coffee kerberos ldap proxy-server'
            self.assertEquals(expected, pipeline)

    def test_nonexistent_constraints(self):
        config_text = dedent(self.basic_config) + dedent("""
            [filter:deluded]
            pipeline = main
            before = doesnotexist
            after = provides:nonexistent 
            
            [filter:fool]
            pipeline = main
            provides = authorization
            before = imaginary, figmental
            after = illusive; fictional; hallucinatory 
            """)
        
        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:main', 'pipeline')
            expected = set(['catch_errors', 'proxy-server', 'deluded', 'fool'])
            actual = set(re.split('\s+', pipeline))
            self.assertEquals(expected, actual)

    def test_multiple_pipelines(self):
        config_text = dedent(self.basic_config) + dedent("""
            [pipeline:secondary]
            dynamic = 1
            pipeline = process_successes proxy-server

            [pipeline:shouldbeignored]
            pipeline = proxy-server 

            [filter:shortbus]
            pipeline = main 
            after = catch_errors process_successes 
            before = proxy-server
            
            [filter:amalgamut]
            pipeline = main secondary
            before = catch_errors process_successes

            [filter:not_present_in_a_pipeline]
            before = catch_errors

            [filter:targets_a_nonexistent_pipeline]
            pipeline = doesnotexist
            before = catch_errors
            """)
        
        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:main', 'pipeline')
            expected = 'amalgamut catch_errors shortbus proxy-server'
            self.assertEquals(expected, pipeline)

            pipeline = config.get('pipeline:secondary', 'pipeline')
            expected = 'amalgamut process_successes proxy-server'
            self.assertEquals(expected, pipeline)

            pipeline = config.get('pipeline:shouldbeignored', 'pipeline')
            self.assertEquals('proxy-server', pipeline)

    def test_special_symbols(self):
        config_text = dedent(self.basic_config) + dedent("""
            [filter:early]
            pipeline = main
            provides = authentication
            before = #start 

            [filter:yet-earlier]
            pipeline = main
            provides = authentication
            before = #start early 
            
            [filter:late]
            pipeline = main
            provides = authorization
            after = #end 

            [filter:yet-later]
            pipeline = main
            after = #end 
            """)

        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:main', 'pipeline')
            expected = 'yet-earlier early catch_errors ' + \
                       'late yet-later proxy-server'
            self.assertEquals(expected, pipeline)

    def test_duplicate_items(self):
        config_text = dedent(self.basic_config) + dedent("""
            [pipeline:duplicates]
            dynamic = 1
            pipeline = filtera filterb filtera filterb proxy-server

            [filter:filtera]
            pipeline = duplicates

            [filter:filterb]
            pipeline = duplicates
            """)

        with temp_config(config_text) as config:
            pipeline = config.get('pipeline:duplicates', 'pipeline')
            expected = 'filtera filterb filtera filterb proxy-server'
            self.assertEquals(expected, pipeline)

    def test_nothing_goes_after_app(self):
        config_text = dedent(self.basic_config) + dedent("""
            [filter:after_app]
            pipeline = main
            after = proxy-server
            """)

        with temp_config(config_text) as exception:
            self.assertEquals(ValueError, exception.__class__)

if __name__ == '__main__':
    unittest.main()
