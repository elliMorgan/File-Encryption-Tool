

class Status:
	message_color='\033[33m'
	good_color='\033[32m'
	bad_color='\033[31m'
	reset_color='\033[39m'


	@staticmethod
	def status_good(*args, **kwargs):
		print(f'{Status.good_color}[+]{Status.reset_color}', *args, **kwargs)


	@staticmethod
	def status_message(*args, **kwargs):
		print(f'{Status.message_color}[*]{Status.reset_color}', *args, **kwargs)


	@staticmethod
	def status_bad(*args, **kwargs):
		print(f'{Status.bad_color}[-]{Status.reset_color}', *args, **kwargs)

