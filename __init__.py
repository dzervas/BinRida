"""
binrida.py - Stalk,dump and instrumentation with Frida

Copyright (c) 2019 Andrea Ferraris

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""
import asyncio
import binaryninja as bn
import binaryninjaui as ui
from threading import Thread
from .actions import *
from .console import CONSOLE
from .settings import SETTINGS
from .log import *

bn.PluginCommand.register("Frinja\\Settings", "Set up Frinja to your liking", SETTINGS.show)
bn.PluginCommand.register("Frinja\\Help", "Show the project readme", show_help)
bn.PluginCommand.register_for_function("Frinja\\Hook Function", "Mark function for hooking during run", mark_hooked)
bn.PluginCommand.register("Frinja\\Run Hooker", "Start frida with the given settings and the hooker script", frida_start)
bn.PluginCommand.register_for_function("Frinja\\Inspect Function Paths", "Highlight the code paths that the functions takes", function_inspector)
bn.PluginCommand.register_for_function("Frinja\\Dump Function Context", "Create a report of all the function calls and returns", function_dumper)
bn.PluginCommand.register("Frinja\\Log Sniffer", "Try to identify logging functions that are called", log_sniffer)

try:
	import murx_devi_binja
	bn.PluginCommand.register_for_function("Frinja\\Devirtualize Virtual calls (devi plugin)", "Generate a devi virtual calls report and call the plugin", devi)
	info("devi plugin found, enabling devi support")
except ImportError:
	warn("devi plugin not found, disabling devi support")
	pass

# try:
# 	import Vector35_snippets
# 	from .snippets import *
# 	info("snippets plugin found, enabling snippets support")
# except ImportError:
# 	info("snippets plugin not found, disabling snippets support")

ui.GlobalArea.addWidget(lambda _: CONSOLE)

# Create async event loop in a thread if not already created
try:
	asyncio.get_event_loop()
except RuntimeError:
	log("Creating new event loop")

	def run_loop():
		asyncio.set_event_loop(asyncio.new_event_loop())
		asyncio.get_event_loop().run_forever()

	Thread(target=run_loop, daemon=True).start()
