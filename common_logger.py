#!/usr/bin/env python3
"""
Common logging for Python scripts and CLI programs.
"""

import argparse
import datetime
import inspect
import logging
import logging.config
import logging.handlers
import os.path
import socket
import sys

import dateutil.tz
import psutil
import pytz

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL
FATAL = logging.FATAL

# FIXME: Come up with a better method for determining the OS-specific paths, etc.
#        Particularly the linux/linux2 thing.
PLATFORM_DEFS = {
    'darwin': {
        'socket': '/var/run/syslog',
        'logdir': os.path.expanduser('~/Library/Logs'),
    },
    # Python2
    'linux2': {
        'socket': '/dev/log',
        'logdir': '/srv/log',
    },
    # Python3
    'linux': {
        'socket': '/dev/log',
        'logdir': '/srv/log',
    },
}


class UcFormatter(logging.Formatter):
    """
    Class for formatting the date & time correctly when logging
    """

    @staticmethod
    def _get_local_tz_str():
        """
        Method to fetch the correct location-string for the local timezone

        e.g. returns "Europe/London"
        """
        # pylint: disable=protected-access
        return '/'.join(
            os.path.realpath(dateutil.tz.gettz()._filename).split('/')[-2:]
        )  # pyright: reportGeneralTypeIssues=false

    def converter(self, timestamp):
        """
        Method to add the local timezone to the the provided timestamp
        """
        tsdt = datetime.datetime.fromtimestamp(timestamp)
        tzinfo = pytz.timezone(self._get_local_tz_str())

        return tzinfo.localize(tsdt)

    def formatTime(self, record, datefmt=None):
        """
        Method to format the timestamp for the log record
        """
        recdt = self.converter(record.created)
        if datefmt:
            return recdt.strftime(datefmt)
        else:
            try:
                return recdt.isoformat(timespec='seconds')
            except TypeError:
                return recdt.isoformat()


class Logger(object):
    """
    Class for implementing a consistent logging format and location
    """

    source = None
    enable_logfile = True

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        logname=None,
        level=INFO,
        enable_logfile=True,
        syslog_facility=logging.handlers.SysLogHandler.LOG_USER,
        logpath=PLATFORM_DEFS[sys.platform]['logdir'],
    ):
        self.enable_logfile = enable_logfile

        # Configure logging basics
        logger = logging.getLogger()
        logging.config.dictConfig(
            {
                'version': 1,
                'disable_existing_loggers': True,
            }
        )
        logger.setLevel(level)

        # Add stream handler
        stream_handler = logging.StreamHandler()
        logger.addHandler(stream_handler)

        if logname:
            self.source = logname
        else:
            self._get_source()

        # Set log formatting
        basefmt = '%(levelname)s {}: %(message)s'.format(self.source)
        local_fmt = UcFormatter(
            fmt='%(asctime)s {}'.format(basefmt),
            datefmt='%Y-%m-%d %H:%M:%S %z',
        )
        syslog_fmt = logging.Formatter(fmt=basefmt)

        # Set formatter for StreamHandler
        stream_handler.setFormatter(local_fmt)

        if self.enable_logfile:
            # Set file handler
            try:
                file_handler = logging.handlers.TimedRotatingFileHandler(
                    os.path.join(
                        logpath,
                        '{}.log'.format(os.path.splitext(self.source)[0]),
                    ),
                    when='midnight',
                    backupCount=90,
                )
            except IOError as error:
                logging.warning('FileHandler: %s', error)
            else:
                # Configure main logger with file handler
                file_handler.setFormatter(local_fmt)
                logger.addHandler(file_handler)

        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=PLATFORM_DEFS[sys.platform]['socket'],
                facility=syslog_facility,
            )
        except socket.error as error:
            logging.warning(
                'SyslogHandler: %s: %s',
                error,
                PLATFORM_DEFS[sys.platform]['socket'],
            )
        else:
            syslog_handler.setFormatter(syslog_fmt)
            logger.addHandler(syslog_handler)

        self.logger = logger

    def _get_source(self):
        """
        Internal method to determine the calling script.

        Uses stack inspection and the OS process list.
        """
        if __name__ == '__main__':
            # Called as a command
            # Get parent process's file
            try:
                open_files = psutil.Process().parent().open_files()
            except psutil.AccessDenied:
                open_files = []

            if open_files:
                self.source = os.path.basename(open_files[0].path)
            else:
                # Being called directly.  No logfile.
                logging.warning(
                    'Unable to determine calling script.  Not writing to disk.'
                )
                self.enable_logfile = False
                self.source = '%(module)s'
        else:
            # Called as a Python module
            self.source = os.path.basename(
                inspect.getframeinfo(inspect.stack()[-1][0]).filename
            )

    # Override built-in method
    # pylint: disable=invalid-name
    def setLevel(self, level):
        """
        Method to set the logging level
        """
        self.logger.setLevel(level)

    # FIXME: Somehow remove the redundancy below (functools.partial?)
    def debug(self, *args, **kwargs):
        """
        Method to log a debug level message.
        """
        self.logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        """
        Method to log an info level message.
        """
        self.logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        """
        Method to log a warning level message.
        """
        self.logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        """
        Method to log an error level message.
        """
        self.logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        """
        Method to log an critical level message.
        """
        self.logger.critical(*args, **kwargs)

    # Alias some of the methods
    warn = warning
    fatal = critical
    exception = error


if __name__ == '__main__':

    def parse_args():
        """
        Function to parse the CLI arguments
        """
        parser = argparse.ArgumentParser()

        group = parser.add_mutually_exclusive_group()
        for level in ['debug', 'info', 'warning', 'error']:
            group.add_argument(
                '-{}'.format(level[0]),
                '--{}'.format(level),
                action='store_true',
                help='log message at level {}'.format(level.upper()),
            )

        parser.add_argument(
            '-n',
            '--name',
            nargs=1,
            default=[None],
            help='basename of the log file to write to',
        )

        parser.add_argument(
            'message',
            nargs=argparse.REMAINDER,
            help='message to log.  Reads STDIN if not provided.',
        )

        return parser.parse_args()

    def main():
        """
        Main entrypoint for the CLI
        """
        args = parse_args()

        logger = Logger(args.name[0])

        if args.debug:
            log = logger.debug
        elif args.info:
            log = logger.info
        elif args.warning:
            log = logger.warning
        elif args.error:
            log = logger.error
        else:
            # Default to INFO
            log = logger.info

        if args.message:
            log(' '.join(args.message))

        # Check if we have data from stdin
        if not sys.stdin.isatty():
            data = sys.stdin.read().strip()
            if data:
                for line in data.split('\n'):
                    log(line)

    main()
