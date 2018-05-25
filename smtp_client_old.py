'''SMTP Client'''
import base64
import socket
import ssl
import logging
import json
import os.path

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


CRLF = '\r\n'

class SmtpClient:
		def __init__(self, client_config_json_path):
				logging.basicConfig(level=logging.DEBUG, format='')
				with open(client_config_json_path) as config_file:
						config = json.load(config_file)

				self.mail_server_config = config['mail_server_config']
				self.mail_server_domain = self.mail_server_config['domain']	 
				self.mail_server_port = self.mail_server_config['port']								 
				self.user_credentials = config['user_credentials']

				self.ssl_sock = ssl.wrap_socket(socket.socket())
				self.ssl_sock.settimeout(3)			 

		def send_letter(self, letter_config_json_path):			
			with open(letter_config_json_path, encoding='utf-8') as config_file:
				letter_config = json.load(config_file)

			recipients = letter_config['recipients']
			subject = letter_config['subject']
			letter_text = letter_config['letter_path']
			attachment_paths = letter_config['attachment_paths']

			with open(letter_config["letter_path"], encoding='utf-8') as letter_file:
				letter_text = letter_file.read()
			data = self.create_letter(recipients, subject, letter_text, attachment_paths)

			try:
				self.connect()
				self.ehlo()
				self.authanticate()
				# TODO: auth error
				self.mail_from(self.user_credentials['mail_address'] + self.mail_server_config["mail_suffix"])
				for recipient in recipients:					
					self.rcpt_to(recipient)
				self.data()			 
				self.send_data(data)
				self.quit()
			except OSError:
				print('Some error occured.')

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
			logging.info('# Connecting to {0}:{1}'.format(self.mail_server_domain, self.mail_server_port))
			self.ssl_sock.connect((self.mail_server_domain, self.mail_server_port))
			return self._receive()

		def ehlo(self):		 
			return self._send('EHLO {0}'.format(self.user_credentials['mail_address']))

		def authanticate(self):		 
			self._auth_decode(self.auth('LOGIN'))
			self._send_b64(self.user_credentials['username'])
			password_response = self._send_b64(self.user_credentials['password'])
			password_response_code = self._get_response_code(password_response)		
			if password_response_code != 250:
				print('Faulted: Authantication faild. Wrong password.')
				return False			
				
			return True
		
		def _get_response_code(self, response):
			return int(response[:3])

		def auth(self, auth_type):							  
			return self._send('AUTH {0}'.format(auth_type))

		def mail_from(self, mail_address): 
			#return self._send('MAIL FROM:<{0}> SIZE={1}'.format(mail_address, size))
			return self._send('MAIL FROM:<{0}>'.format(mail_address))

		def rcpt_to(self, mail_address):
			return self._send('RCPT TO:<{0}>'.format(mail_address))

		def data(self):
			return self._send('DATA')

		def send_data(self, message):
			return self._send(message + '\r\n.\r\n')

		def quit(self):						 
			return self._send('QUIT')

		def _send(self, command):
			logging.info('# {0}'.format(command))
			self.ssl_sock.send((command + CRLF).encode())
			return self._receive()		  

		def _send_b64(self, command):
			return self._send(base64.b64encode(command.encode()).decode())

		def _auth_decode(self, response):
			return base64.b64decode(response.split()[1]).decode()

		def _receive(self, count=1024):
			response = self.ssl_sock.recv(count)
			decoded_b64 = '({0})'.format(self._auth_decode(response)) if response[:3] == b'334' else ''
			logging.info('{0} {1}\r\n'.format(response.decode()[:-2], decoded_b64))
			return response

		def close(self):				
			self.ssl_sock.close()


client = SmtpClient("smtp_client_config.json")
client.send_letter("test_letter_config.json")
client.close()
