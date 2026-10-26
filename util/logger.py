import logging

log = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s:%(levelname)-7s:%(filename)s:%(funcName)s:%(lineno)d:%(message)s",
    filename='debug.log',
    encoding='utf-8',
    level=logging.DEBUG
)

def inf(text):
    log.info(text)

def wrn(text):
    log.warning(text)

def dbg(text):
    log.debug(text)

def err(text):
    log.error(text)

def critical(text):
    log.critical(text)