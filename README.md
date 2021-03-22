# Common Logger

A Python library to allow for logging consistently across multiple scripts to ensure logs are stored in a known location.  Includes daily rotation and deletion of stale log files.

## Python usage
Example:
```python
import common_logger

logging = common_logger.Logger(level=common_logger.DEBUG)

logging.debug('Could not find the %s.', 'cat')
logging.info('Hello World!')
logging.warn('Be careful!')
logging.error('Something terrible has happened')
```

```plain
$ cat /srv/log/example.log
2021-03-22 16:19:34 +0000 DEBUG example.py: Could not find the cat.
2021-03-22 16:19:34 +0000 INFO example.py: Hello World!
2021-03-22 16:19:34 +0000 WARNING example.py: Be careful!
2021-03-22 16:19:34 +0000 ERROR example.py: Something terrible has happened
```

## Command line usage
```plain
usage: common_logger.py [-h] [-d | -i | -w | -e] [-n NAME] ...

positional arguments:
  message               message to log. Reads STDIN if not provided.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           log message at level DEBUG
  -i, --info            log message at level INFO
  -w, --warning         log message at level WARNING
  -e, --error           log message at level ERROR
  -n NAME, --name NAME  basename of the log file to write to
```

Example:
```shell
echo 'Hello world!' | ./common_logger.py -n example
```

```plain
$ cat /srv/log/example.log 
2021-03-22 16:15:10 +0000 INFO example: Hello world!
```