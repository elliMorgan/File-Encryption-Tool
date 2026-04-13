#!/usr/bin/env python3
import sys


class StatusBar:
	def __init__(self, task, end=100, status='', in_progress_color='\033[33m', success_color='\033[32m', fail_color='\033[31m', reset_color='\033[39m', bar_char='▊'):
		self._task = task
		self._in_progress_color = in_progress_color
		self._success_color = success_color
		self._fail_color = fail_color
		self._reset_color = reset_color
		self._progress = 0
		self._end = end
		self._percent = (self._progress/self._end)*100
		self._bar_char = bar_char
		self._finished = False
		self._clear_line = '\033[2K'
		print(f'{task}:')
		print(f'\r{self._in_progress_color}|{self._bar_char*int(self._percent):100}| {(self._progress/self._end)*100:.2f}% ({self._progress}/{self._end}) {status}{self._reset_color}\r', end='')


	def update(self, amount=1, status=''):
		self._progress += amount
		self._percent = (self._progress/self._end)*100
		if self._finished:
			return
		if self._progress > self._end:
			self.fail('The current progress has exceeded the end.')
			return
		print(f'\r{self._clear_line}{self._in_progress_color}|{self._bar_char*int(self._percent):100}| {(self._progress/self._end)*100:.2f}% ({self._progress}/{self._end}) {status}{self._reset_color}\r', end='\r')
		if self._progress == self._end:
			print(f'\r{self._clear_line}{self._success_color}|{self._bar_char*int(self._percent):100}| {(self._progress/self._end)*100:.2f}% ({self._progress}/{self._end}) (COMPLETE) {status}{self._reset_color}')
			self._finished = True


	def fail(self, status='', exit=True, finish=True, amount=1):
		if self._finished:
			return
		print(f'\r{self._clear_line}{self._fail_color}|{self._bar_char*int(self._percent):100}| {(self._progress/self._end)*100:.2f}% ({self._progress}/{self._end}) (FAILED) {status}{self._reset_color}', end=('\n' if (exit or finish) else '\r'))
		if exit:
			sys.exit(1)
		self._finished = finish
		if not finish:
			self._percent = (self._progress/self._end)*100
			self._progress+=amount
			if self._progress == self._end:
				print(f'\r{self._clear_line}{self._fail_color}|{self._bar_char*int(self._percent):100}| {(self._progress/self._end)*100:.2f}% ({self._progress}/{self._end}) (FAILED) {status}{self._reset_color}')
