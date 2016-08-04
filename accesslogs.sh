#!/bin/bash
#Author JonathanW
#This script will be used for analysing access logs for traffic anomolies

# Detect access log location and also if not mac
os=$(uname)
if [ $os != "Darwin" ]; then
  if [[ $(netstat -nap | grep ':::80' | awk -F'/' '{print $2}') = *nginx* ]]; then accessLogsLocation="/var/log/nginx/"; fi
  if [[ $(netstat -nap | grep ':::80' | awk -F'/' '{print $2}') = *httpd* ]]; then accessLogsLocation="/var/log/httpd/"; fi
  if [[ $(netstat -nap | grep ':::80' | awk -F'/' '{print $2}') = *apache2* ]]; then accessLogsLocation="/var/log/apache2/"; fi
  if [ -e "/usr/local/cpanel/cpanel" ]; then accessLogsLocation="/usr/local/apache/domlogs/"; fi
fi

# Set your variables
accessLogs=$(find $accessLogsLocation -type f -name '*access*log' -print0 | xargs -0 du | sort -n | tail -50 | cut -f2 | xargs -I{} du -sh {} | awk '{print $2}')
currentDate=$(date +"%d/%b/%Y")
currentMonth=$(date +"/%b/%Y")

# Functions to rule them all mwahahaha
function todaysLogs {
  echo "Todays access logs:"; echo "Top IP addresses:"
  cat $accessLogs | grep $currentDate | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top URLs:"
  cat $accessLogs | grep $currentDate | awk '{print $7}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top referrers:"
  cat $accessLogs | grep $currentDate | awk '{print $11}' | tr -d '"' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top User Agents: "
  cat $accessLogs | grep $currentDate | cut -d\  -f12- | sort | uniq -c | sort -rn | head -10
}

# Functions to rule them all mwahahaha
function monthlyLogs {
  echo "Entire recent access log:"
  echo "Top IP addresses:"
  cat $accessLogs | grep $currentMonth | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top URLs:"
  cat $accessLogs | grep $currentMonth | awk '{print $7}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top referrers:"
  cat $accessLogs | grep $currentMonth | awk '{print $11}' | tr -d '"' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top User Agents: "
  cat $accessLogs | grep $currentMonth | cut -d\  -f12- | sort | uniq -c | sort -rn | head -10
}

# Functions to rule them all mwahahaha
function everythingLogs {
  echo "Entire recent access log:"
  echo "Top IP addresses:"
  cat $accessLogs | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top URLs:"
  cat $accessLogs | awk '{print $7}' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top referrers:"
  cat $accessLogs | awk '{print $11}' | tr -d '"' | sort | uniq -c | sort -rn | head -10
  echo; echo "Top User Agents: "
  cat $accessLogs | cut -d\  -f12- | sort | uniq -c | sort -rn | head -10
}

# Wordpress brute force attack detection
function wpBruteForce {
  echo "Dected wp-login.php attacks:"
  for f in $accessLogs
  do
    if [[ -n $(cat $f | awk '{print $7}' | sort | uniq -c | sort -rn | head -10 | grep wp-login.php) ]]; then
      d=$(echo $f | grep -oE '[[:alnum:]]+[.][[:alnum:]_.-]+')
      echo "$d: "
      cat $f | awk '{print $7}' | sort | uniq -c | sort -rn | head -10 | grep wp-login.php
    else
      echo -ne ""
    fi
  done
}

# xmlrpc.php DDoS detection
function xmlrpcAttack {
  echo "Dected xmlrpc.php attacks:"
  for f in $accessLogs
  do
    if [[ -n $(cat $f | awk '{print $7}' | sort | uniq -c | sort -rn | head -10 | grep xmlrpc.php) ]]; then
      d=$(echo $f | grep -oE '[[:alnum:]]+[.][[:alnum:]_.-]+')
      echo "$d: "
      cat $f | awk '{print $7}' | sort | uniq -c | sort -rn | head -10 | grep xmlrpc.php
    else
      echo -ne ""
    fi
  done
}

# Last ten hits
function lastTen {
  echo "Last ten hits from $ipAddress:"
  cat $accessLogs | grep $ipAddress | tail -10
}

# Standard input(stdin) magic ooooo ahhhh
function stdin {
  if [[ -p /dev/stdin ]]
  then
    rm -f /tmp/access_logs_stdin
    touch /tmp/access_logs_stdin
    # Did you know that $(cat) is a shorthand for $(cat /dev/stdin)? I certainly didn't.
    cat > /tmp/access_logs_stdin
    accessLogs="/tmp/access_logs_stdin"
  fi
}

function usage {
    echo "usage: accesslogs"
    echo "	-a   Last ten hits from specified IP address"
    echo "	-d   Specify access log directory"
    echo "	-e   Analyze entire log history"
    echo "	-f   Specify individual access log"
    echo "	-x   Detect xmlrpc attacks(Only for today's date)"
    echo "	-w   Detect Wordpress brute force attacks(Only for today's date)"
    echo "	-h   Display usage information"
    echo "	-s   Grab logs from Standard Input(stdin/pipeline)"
    echo "	-t   Analyze todays logs"
    echo "	-m   Analyze logs this month"
    exit 1
}

# I have options?!?
while getopts a:d:ef:hmstwx option
  do case "${option}" in
    a) ipAddress=$OPTARG; lastTen;;
    d) accessLogsLocation=$OPTARG; accessLogs=$(find $accessLogsLocation -type f -name '*access_log' -print0 | xargs -0 du | sort -n | tail -50 | cut -f2 | xargs -I{} du -sh {} | awk '{print $2}');;
    e) everythingLogs;echo;;
    f) accessLogsLocation=$OPTARG; accessLogs=$accessLogsLocation;;
    h) usage;;
    m) monthlyLogs;echo;;
    s) stdin;;
    t) todaysLogs;echo;;
    w) wpBruteForce;echo;;
    x) xmlrpcAttack;echo;;
  esac
done

if [ $# -eq 0 ];
then
    usage
    exit 0
fi

