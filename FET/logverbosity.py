#!/usr/bin/env python3

import datetime
import logging
from errors import InvalidOptionsError


class LogVerbosityCheck:
	def __init__(self, verbose=False, start_time=datetime.datetime.today(), *args, **kwargs):
		self._log_verbose = verbose
		self._logger = logging.getLogger(*args, **kwargs)
		self._start_time = start_time


	def setLogVerbose(self, verbose):
		self._log_verbose = verbose


	def callIfLogVerbose(self, func, *args, **kwargs):
		if self._log_verbose:
			func(*args, **kwargs)


	def log_with_date_and_time_if_v(self, msg, time=datetime.datetime.today()):
		self.callIfLogVerbose(self._logger.info, f'{time}:{msg}')


	def warn_with_date_and_time_if_v(self, msg):
		self.callIfLogVerbose(self._logger.warning, f'{datetime.datetime.today()}:{msg}')


	def init_log_verbosity_check(self, log, log_file):
		self.setLogVerbose(log)
		if log and not log_file:
			raise InvalidOptionsError('If log is set to true, log_file must be a filename.')
			sys.exit(1)
		elif log and log_file:
			logging.basicConfig(filename=log_file, level=logging.INFO)
			self.log_with_date_and_time_if_v(f"Program initiated.", self._start_time)


	def atexitFunc(self):
		exit_time = datetime.datetime.today()
		self.log_with_date_and_time_if_v(f"Exiting program({exit_time.timestamp() - self._start_time.timestamp()} seconds).")


