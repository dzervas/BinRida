from threading import Thread
import binaryninjaui as ui
import json
import frida
import time
import asyncio

from .log import *
from .settings import SETTINGS
from .helper import PLUGIN_PATH
from html import escape
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from PySide6.QtWidgets import QVBoxLayout, QTextBrowser, QLineEdit, QLabel, QHBoxLayout, QPushButton, QWidget
from PySide6.QtGui import QTextCursor, QIcon, QAction, QContextMenuEvent
from PySide6.QtCore import Qt, QUrl

ICONS_PATH = PLUGIN_PATH / "icons"

CSS = f"""
a {{ text-decoration: none; }}
a[href^="function"] {{ color: {ui.getThemeColor(bn.ThemeColor.CodeSymbolColor).name()}; }}
a[href^="address"] {{ color: {ui.getThemeColor(bn.ThemeColor.AddressColor).name()}; }}
"""

def on_anchor_click(url: QUrl):
	bv: bn.BinaryView = ui.UIContext.activeContext().getCurrentView().getData()

	target = url.path().strip()
	try:
		target = int(target, 16)
	except ValueError:
		try:
			target = int(target)
		except ValueError:
			pass

	if url.scheme() == "function":
		func = bv.get_function_at(target)
		if func:
			bv.navigate(bv.view, func.start)
		else:
			alert(f"Function not found at: {url.path()}")
	elif url.scheme() == "address":
		bv.navigate(bv.view, target)

# Got from https://github.com/frida/frida-tools/blob/main/frida_tools/repl.py#L1188
def hexdump(src, length: int = 16) -> str:
	FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
	lines = []
	for c in range(0, len(src), length):
		chars = src[c : c + length]
		hex = " ".join(["%02x" % x for x in iter(chars)])
		printable = "".join(["%s" % ((x <= 127 and FILTER[x]) or ".") for x in iter(chars)])
		lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
	return "".join(lines).rstrip("\n")


class HistoryLineEdit(QLineEdit):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.history = []
		self.history_pos = -1

	def keyPressEvent(self, event):
		if event.key() == Qt.Key.Key_Up:
			if self.history_pos < len(self.history) - 1:
				self.history_pos += 1
				self.setText(self.history[self.history_pos])
		elif event.key() == Qt.Key.Key_Down:
			if self.history_pos > 0:
				self.history_pos -= 1
				self.setText(self.history[self.history_pos])
			else:
				self.history_pos = -1
				self.clear()
		else:
			super().keyPressEvent(event)

	def loadHistory(self):
		self.history = SETTINGS.console_history
		self.history_pos = -1

	def addToHistory(self, command):
		try:
			self.history.remove(command)
		except ValueError:
			pass

		self.history_pos = -1
		self.history.insert(0, command)

		if len(self.history) > 4096:
			self.history = self.history[:4096]

		SETTINGS.console_history = self.history


class ConsoleTextBrowser(QTextBrowser):
	_last_update: float
	_queue: asyncio.Queue
	_throttled_update: Optional[asyncio.Task]

	def __init__(self, parent: QWidget | None = ...) -> None:
		super().__init__(parent)

		self._last_update = 0
		self._queue = asyncio.Queue()
		self._throttled_update = None

	def contextMenuEvent(self, event: QContextMenuEvent):
		self.setUndoRedoEnabled(False)
		self.setReadOnly(True)
		menu = self.createStandardContextMenu()
		menu.addSeparator()

		# Add custom action to clear the text
		clearAction = QAction("Clear Console", self)
		clearAction.triggered.connect(self.clear_text)
		menu.addAction(clearAction)

		# Display the context menu
		menu.exec(event.globalPos())

	def appendHtml(self, html: str, sync: bool = False):
		# TODO: Fix the throttler
		sync = True

		if not isinstance(html, str):
			alert(f"appendHtml called with non-string argument: {str(html)}")
			return

		if not sync and self._throttled_update is not None and not self._throttled_update.done():
			self._queue.put_nowait(html)
		elif not sync and time.time() - self._last_update < 0.35:
			self._queue.put_nowait(html)

			if not self._throttled_update:
				self._throttled_update = asyncio.create_task(self._appendHtml_throttler())
		else:
			self.moveCursor(QTextCursor.End)
			self.insertHtml(f"<style>{CSS}</style><br/>{html}")

			self._last_update = time.time()

	async def _appendHtml_throttler(self):
		html = ""
		await asyncio.sleep(0.3)
		while True:
			try:
				html += self._queue.get_nowait() + "<br/>"
			except asyncio.QueueEmpty:
				break

		html = html[:-len("<br/>")]
		self._throttled_update = None

		def callback():
			self._throttled_update = None
			self.appendHtml(html, sync=True)

		bn.execute_on_main_thread(callback)

	def clear_text(self):
		self.clear()


class FridaConsoleWidget(ui.GlobalAreaWidget):
	_evaluate_cb: Optional[Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]]] = None
	_stop_cb: Optional[Callable[[], None]] = None

	input: HistoryLineEdit
	output: QTextBrowser
	play_stop: QPushButton
	hook: QPushButton
	save: QPushButton

	def __init__(self):
		super().__init__("Frida Console")

		layout = QVBoxLayout()

		self.output = ConsoleTextBrowser(self)
		self.output.setOpenLinks(False)
		self.output.setOpenExternalLinks(False)
		self.output.anchorClicked.connect(on_anchor_click)
		layout.addWidget(self.output)

		hbox = QHBoxLayout()
		hbox.addWidget(QLabel(">"))

		self.input = HistoryLineEdit(self)
		self.input.returnPressed.connect(self.on_input_handler)
		hbox.addWidget(self.input)

		self.play_stop = QPushButton(parent=self)
		self.play_stop.clicked.connect(self.on_play_stop)
		hbox.addWidget(self.play_stop)

		self.save = QPushButton(parent=self)
		self.save.setIcon(QIcon(str(ICONS_PATH / "floppy-disk-solid.svg")))
		self.save.setToolTip("Save script and console output to file")
		# self.save.clicked.connect(self.on_save)
		hbox.addWidget(self.save)

		self.hook = QPushButton(parent=self)
		self.hook.setIcon(QIcon(str(ICONS_PATH / "code-branch-solid.svg")))
		self.hook.setToolTip("Mark the current function to be hooked")
		self.hook.clicked.connect(self.on_hook)
		hbox.addWidget(self.hook)

		layout.addLayout(hbox)
		self.setLayout(layout)

		self.session_end(showFinished=False)

	@alert_on_error
	def on_input_handler(self):
		if not self._evaluate_cb:
			self.output.appendHtml("Internal Error: No evaluate function set")
			return

		text = self.input.text()
		self.input.addToHistory(text)
		self.input.clear()
		self.output.appendHtml(f"> {text}")

		# result = self._evaluate_cb(text)
		# self.handle_result(result)
		@alert_on_error
		def eval_bg():
			result = self._evaluate_cb(text)
			bn.execute_on_main_thread_and_wait(lambda: self.handle_result(result))

		Thread(target=eval_bg).start()

	def on_play_stop(self):
		if self._evaluate_cb:
			self._stop_cb()
			self.session_end()
		else:
			bv = ui.UIContext.activeContext().getCurrentView().getData()
			ctx = bn.PluginCommandContext(bv)
			bn.PluginCommand.get_valid_list(ctx)["Frinja\\Run Hooker"].execute(ctx)

	def on_hook(self):
		bv = ui.UIContext.activeContext().getCurrentView().getData()
		func = ui.UIContext.activeContext().getCurrentView().getCurrentFunction()
		ctx = bn.PluginCommandContext(bv)
		ctx.function = func
		bn.PluginCommand.get_valid_list(ctx)["Frinja\\Hook Function"].execute(ctx)

	def session_start(self, evaluate: Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]], stop: Callable[[], None]):
		if not evaluate:
			alert("Frinja: No evaluate function set for console on session start")
			return

		self._evaluate_cb = evaluate
		self._stop_cb = stop

		self.input.clear()
		self.input.loadHistory()
		self.input.setReadOnly(False)
		self.input.setFocus()

		self.output.insertHtml("Frida Client v" + str(frida.__version__))
		try:
			self.output.appendHtml("Frida Client v" + evaluate("Frida.version")[1])
		except frida.InvalidOperationError:
			pass

		self.play_stop.setIcon(QIcon(str(ICONS_PATH / "stop-solid.svg")))
		self.play_stop.setToolTip("Stop frida session")
		# self.save.show()

	def session_end(self, showFinished: bool = True):
		self.input.setReadOnly(True)
		self.input.setText("Please use the `Start Hooker` command to start a session")
		self._evaluate_cb = None
		self.input.history = []

		self.play_stop.setIcon(QIcon(str(ICONS_PATH / "play-solid.svg")))
		self.play_stop.setToolTip("Start frida session")
		self.save.hide()

		if showFinished:
			self.output.appendHtml("<br/>=== Script finished ===<br/>")

	def handle_result(self, result: Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]):
		if result[0] == "error":
			error = result[1]
			line = f'<span style="color: red;"><b>{escape(error["name"])}</b></span>: {escape(error["message"])}'

			if "stack" in error.keys():
				message_len = len(error["message"].split("\n"))
				# trim_amount = 6 if self._runtime == "v8" else 7
				trimmed_stack = error["stack"].split("\n")[message_len:-6]
				if len(trimmed_stack) > 0:
					output += "<br/>" + "<br/>".join(trimmed_stack)

			self.output.appendHtml(line)
			return

		if isinstance(result, bytes):
			self.output.appendHtml(escape(hexdump(result)))
		elif isinstance(result, dict):
			warn(f"dict instance {str(result)}")
		elif result[0] in ("function", "undefined", "null"):
			self.output.appendHtml(escape(result[0]))
		else:
			self.output.appendHtml(escape(json.dumps(result[1], sort_keys=True, indent=4, separators=(",", ": "))))

	def handle_log(self, level: str, text: str):
		line = escape(text).replace("\n", "<br/>")

		if level == "debug":
			line = f'<span style="color: gray;"><b>[d]</b></span> <i>{line}</i>'
		elif level == "info":
			line = f'<span style="color: blue;"><b>[+]</b></span> {line}'
		elif level == "warning":
			line = f'<span style="color: yellow;"><b>[!]</b></span> {line}'
		elif level == "error":
			line = f'<span style="color: red;"><b>[x]</b> {line}</span>'

		self.output.appendHtml(line)

	def handle_message(self, msg: Any):
		self.output.appendHtml(escape("< " + str(msg)))

	def handle_error(self, msg: frida.core.ScriptErrorMessage):
		for k in msg.keys():
			try:
				msg[k] = escape(msg[k])
			except Exception:
				pass

		self.output.appendHtml(f"<span style='color: red;'><b>{msg['description']}</b></span>")
		if "stack" in msg.keys():
			self.output.appendHtml("<span style='color: red;>" + "<br/>".join(msg["stack"].split("\\n")) + "</span>")


CONSOLE = FridaConsoleWidget()
