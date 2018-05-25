'''SMTP Client'''
import base64
import socket
import ssl
import logging
import json
import os.path
import traceback

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


CRLF = '\r\n'

class SmtpClient:
		def __init__(self, client_config_json_path):
				logging.basicConfig(level=logging.DEBUG, format='')
				try:
					with open(client_config_json_path) as config_file:
							config = json.load(config_file)
							self._validate_client_config(config)
				except FileNotFoundError:					
					raise SmtpClientConfigNotFound(f"Client configuration file \"{client_config_json_path}\" is not found")
				except json.decoder.JSONDecodeError:
					raise SmtpClientConfigInvalidFormat(f"Client config \"{client_config_json_path}\" is mal-formed")
				except Exception:
					raise

				self.mail_server_config = config['mail_server_config']
				self.mail_server_domain = self.mail_server_config['domain']	 
				self.mail_server_port = self.mail_server_config['port']								 
				self.user_credentials = config['user_credentials']

				self.ssl_sock = ssl.wrap_socket(socket.socket())
				self.ssl_sock.settimeout(3)

		def _validate_client_config(self, config):
			exception_messages = []
			mapping = {
				'mail_server_config': ('domain', 'port', 'mail_suffix'),
				'user_credentials': ('username', 'password', 'mail_address')
			}

			for config_key in mapping:
				if config_key not in config:
					exception_messages.append(f'Client config must contain \"{config_key}\" field')
				else:				
					for field in mapping[config_key]:
						if field not in config[config_key]:
							exception_messages.append(f'\"{config_key}\" field must contain \"{field}\" field')

			if exception_messages:
				raise Exception('Client config validation errors occured:\n\t' + '\n\t'.join(exception_messages))

		def _validate_letter_config(self, config):
			exception_messages = []
			keys = ('recipients', 'subject', 'letter_path', 'attachment_paths')
			for key in keys:
				if key not in config:
					exception_messages.append(f'Letter config must contain \"{key}\" field')
				elif key == 'letter_path':
					if not os.path.isfile(config[key]):
						exception_messages.append(f'File \"{config[key]}\" does not exist')
				elif key == 'attachment_paths':
					for path in config[key]:
						if not os.path.isfile(path):
							exception_messages.append(f'File \"{path}\" does not exist')

			if exception_messages:
				raise Exception('Letter config validation errors occured:\n\t' + '\n\t'.join(exception_messages))

		def _raise_on_bad_code(self, actual_code, expected_code, error_message):
			if actual_code != expected_code:
				raise Exception(error_message)

		def send_letter(self, letter_config_json_path):
			try:			
				with open(letter_config_json_path, encoding='utf-8') as config_file:
					letter_config = json.load(config_file)
					self._validate_letter_config(letter_config)
			except FileNotFoundError:					
				raise SmtpClientConfigNotFound(f"Letter configuration file \"{letter_config_json_path}\" is not found")
			except json.decoder.JSONDecodeError:
				raise SmtpClientConfigInvalidFormat(f"Letter config \"{letter_config_json_path}\" is mal-formed")
			except:
				raise

			recipients = letter_config['recipients']
			subject = letter_config['subject']
			letter_text = letter_config['letter_path']
			attachment_paths = letter_config['attachment_paths']

			with open(letter_config["letter_path"], encoding='utf-8') as letter_file:
				letter_text = letter_file.read()
			data = self.create_letter(recipients, subject, letter_text, attachment_paths)

			try:
				response_code = self.connect()
				self._raise_on_bad_code(response_code, 220, 'Server refused connection')				

				response_code = self.ehlo()
				self._raise_on_bad_code(response_code, 250, 'Bad response for EHLO command')
				
				response_code = self.authanticate()
				self._raise_on_bad_code(response_code, 235, 'Authantication faild')				

				self.mail_from(self.user_credentials['mail_address'] + self.mail_server_config["mail_suffix"])

				for recipient in recipients:
					response_code = self.rcpt_to(recipient)
					self._raise_on_bad_code(response_code, 250, 'Some recipient address is invalid')
				
				response_code = self.data()
				self._raise_on_bad_code(response_code, 354, 'Server refused to receive data')				

				response_code = self.send_data(data)
				self._raise_on_bad_code(response_code, 250, 'Server has not accept data')				

				self.quit()
			except socket.gaierror:
				raise Exception('Unable to establish connection')
			except (socket.timeout, ConnectionAbortedError, ConnectionResetError):
				raise Exception('Connection reset, lost or aborted')
			except:
				raise		

		def create_letter(self, recipients, subject, text, attachment_paths):
			letter = MIMEMultipart('mixed')
			letter['Subject'] = subject
			letter['To'] = ','.join(recipients)
			
			alternative_block = MIMEMultipart('alternative')			
			alternative_block.attach(MIMEText(text))
			letter.attach(alternative_block)
			
			for path in attachment_paths:
				attachment = MIMEApplication(open(path, 'rb').read())
				attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(path))
				letter.attach(attachment)
			return letter.as_string()
			   
		def connect(self):
			logging.info(f'# Connecting to {self.mail_server_domain}:{self.mail_server_port}.')
			self.ssl_sock.connect((self.mail_server_domain, self.mail_server_port))
			return self._get_response_code(self._receive())

		def ehlo(self):		 
			return self._get_response_code(self.request(f"EHLO {self.user_credentials['mail_address']}"))

		def authanticate(self):		 
			self._auth_decode(self.auth('LOGIN'))
			self.request(self.user_credentials['username'], encodeBase64=True)			
			password_response = self.request(self.user_credentials['password'], encodeBase64=True)
			return self._get_response_code(password_response)		

		def auth(self, auth_type):							  
			return self.request(f'AUTH {auth_type}')

		def mail_from(self, mail_address):			
			return self.request(f'MAIL FROM:<{mail_address}>')

		def rcpt_to(self, mail_address):
			return self._get_response_code(self.request(f'RCPT TO:<{mail_address}>'))

		def data(self):
			return self._get_response_code(self.request('DATA'))

		def send_data(self, message):
			return self._get_response_code(self.request(message + '\r\n.\r\n'))

		def quit(self):						 
			return self.request('QUIT')

		def request(self, command, encodeBase64=False):
			logging.info(f'# {command}')
			if encodeBase64:
				command = base64.b64encode(command.encode()).decode()
			
			self.ssl_sock.send((command + CRLF).encode())
			return self._receive()

		def _auth_decode(self, response):
			return base64.b64decode(response.split()[1]).decode()

		def _receive(self, count=1024):
			response = self.ssl_sock.recv(count)
			decoded_b64 = f'({self._auth_decode(response)})' if response[:3] == b'334' else ''
			logging.info(f'{response.decode()[:-2]} {decoded_b64}\r\n')
			return response

		def _get_response_code(self, response):
			return int(response[:3])

		def close(self):				
			self.ssl_sock.close()

		def __enter__(self):
			return self

		def __exit__(self, type, value, tb):
			self.close()			


class SmtpClientConfigNotFound(Exception):
	pass

class SmtpClientConfigInvalidFormat(Exception):
	pass


def main():
	try:
		with SmtpClient("smtp_client_config.json") as client:
			client.send_letter("test_letter_config.json")			
	except Exception as e:
		print(f'> Faulted: {e}.')


if __name__ == "__main__":
	main()
