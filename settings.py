from enum import Enum
from typing import Optional
from binaryninja import BinaryView
from frida.core import Device
import binaryninja as bn
import frida
from .log import *

HOOK_TAG_TYPE = "Frinja Hooked"
HOOK_TAG_TYPE_ICON = "🪝"


class ExecutionAction(Enum):
	SPAWN = 0
	ATTACH_NAME = 1
	ATTACH_PID = 2


class Settings():
	device: Optional[Device] = None
	exec_action: ExecutionAction = ExecutionAction.SPAWN
	attach_name: str = ""
	attach_pid: Optional[int] = None
	file_target: str = ""
	cmdline: str = ""
	workdir: Optional[str] = None
	console_history: list[str] = []

	# TODO: P2P functionality
	# TODO: Certificate support
	# TODO: Stun server support
	# TODO: Relay server support

	def __init__(self):
		pass

	def show(self, bv: BinaryView):
		self.restore(bv)

		devices = frida.enumerate_devices()

		device_ui = bn.ChoiceField("Device", [d.name for d in devices], [d.id for d in devices].index(self.device.id) if self.device is not None else None)
		exec_action_ui = bn.ChoiceField("Execution mode", ["Spawn a new process", "Attach to process name", "Attach to PID"], self.exec_action.value)

		name_ui = bn.TextLineField("Process Name", self.attach_name)
		pid_ui = bn.ChoiceField("PID", [])
		file_target_ui = bn.TextLineField("File target", self.file_target if self.file_target != "" else bv.file.original_filename)
		cmdline_ui = bn.TextLineField("Command line arguments", self.cmdline)
		workdir_ui = bn.TextLineField("Working directory", self.workdir)

		form = [
			device_ui,
			exec_action_ui,
			bn.SeparatorField(),

			bn.LabelField("Process Name Attaching Settings"),
			name_ui,
			bn.SeparatorField(),

			bn.LabelField("PID Attaching Settings"),
			pid_ui,
			bn.SeparatorField(),

			bn.LabelField("Spawning Settings"),
			file_target_ui,
			cmdline_ui,
			workdir_ui,
		]

		device = self.device if self.device is not None else devices[0]

		try:
			for processes in device.enumerate_processes():
				pid_ui.choices.append(f"{processes.name} ({processes.pid})")
				if self.attach_pid == processes.pid:
					pid_ui._default = len(pid_ui.choices) - 1
		except frida.ServerNotRunningError:
			info("Unable to enumerate PIDs of the device - is the server running?")
			pid_ui.prompt += " (Unable to enumerate PIDs)"

		result = bn.interaction.get_form_input(form, "Frinja Settings")

		if not result:
			return

		self.device = devices[device_ui.result]
		self.exec_action = ExecutionAction(exec_action_ui.result)
		self.attach_name = name_ui.result.strip()
		self.attach_pid = int(pid_ui.choices[pid_ui.result].split("(")[1][:-1]) if pid_ui.result is not None and pid_ui.choices else 0
		self.file_target = file_target_ui.result
		self.cmdline = cmdline_ui.result
		self.workdir = None if workdir_ui.result == "" else workdir_ui.result

		self.store(bv)

	def store(self, bv: BinaryView):
		bv.store_metadata("frinja_device", self.device.id)
		bv.store_metadata("frinja_exec_action", self.exec_action.value)
		bv.store_metadata("frinja_attach_name", self.attach_name)
		bv.store_metadata("frinja_attach_pid", self.attach_pid)
		bv.store_metadata("frinja_cmdline", self.cmdline)
		bv.store_metadata("frinja_workdir", self.workdir)
		bv.store_metadata("frinja_file_target", self.file_target)
		bv.store_metadata("frinja_console_history", self.console_history)

	def restore(self, bv: BinaryView):
		try:
			self.device = frida.get_device(bv.query_metadata("frinja_device"))
			self.exec_action = ExecutionAction(bv.query_metadata("frinja_exec_action"))
			self.cmdline = bv.query_metadata("frinja_cmdline")
			self.workdir = bv.query_metadata("frinja_workdir")
			self.attach_name = bv.query_metadata("frinja_attach_name")
			self.attach_pid = bv.query_metadata("frinja_attach_pid")
			self.file_target = bv.query_metadata("frinja_file_target")
			self.console_history = bv.query_metadata("frinja_console_history")
		except KeyError:
			pass

SETTINGS = Settings()