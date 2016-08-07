# AccessLogsAnaylzer

Analyzes access logs on just about any server.

Features:
- Accepts input from options
- Detects WordPress Brute Force Attacks
- Detects XMLRPC Attacks
- Analyzes traffic anomolies

## Usage

Use the following options with the script to perform different actions. 

	-a   Last ten hits from specified IP address
	-d   Specify access log directory
	-e   Analyze entire log history
	-f   Specify individual access log
	-x   Detect xmlrpc attacks(Only for today's date)
	-w   Detect Wordpress brute force attacks(Only for today's date)
	-h   Display usage information
	-s   Grab logs from Standard Input(stdin/pipeline)
	-t   Analyze todays logs
	-m   Analyze logs this month
