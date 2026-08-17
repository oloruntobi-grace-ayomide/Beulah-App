import os
import sys
import importlib.util

os.environ["TERM"] = "xterm"
sys.path.insert(0, os.path.dirname(__file__))

spec = importlib.util.spec_from_file_location("wsgi", "starter.py")
wsgi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wsgi)

application = wsgi.app