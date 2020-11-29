from datetime import datetime
from pathlib import Path
from time import sleep
from xml import sax
import argparse
import sys
import os


class FirewallHandler():
  def __init__(self):
    ruleIndex = 1
    ips = []
    
    print('Searching rules...')
    
    found = False
    prevLines = None
    while True:
      print('Checking {}...'.format(ruleIndex))
      out = os.popen('netsh advfirewall firewall show rule name="Bitvise SSH Blacklist {}"'.format(ruleIndex))
      lines = out.readlines()
      for l in lines:
        if l.startswith('Rule Name:'):
          prevLines = lines
          break
        if l.startswith('No rules match the specified criteria.'):
          ruleIndex -= 1
          found = True
          break
      if found:
        break
      ruleIndex += 1
      prevLines = lines
    
    if prevLines:
      for line in prevLines:
        if line.startswith('RemoteIP:'):
          for ip in line.split(':')[1].strip().split(','):
            addr, mask = ip.split('/')
            if mask == '32':
              ips.append(addr)
            else:
              ips.append(ip)
          #print(repr(ips))
          break
    
    print('firewall index: {}, IPs: {}'.format(ruleIndex, len(ips)))
    
    self._ruleIndex = ruleIndex
    self._ips = ips
  
  def add(self, ip):
    self._ips.append(ip)
    print(datetime.now())
    
    ipList = ','.join(self._ips)
    if len(ipList) > 8000:
      self._ruleIndex += 1
      self._ips = [ip]
      ipList = ip
      print('Switching to firewall index {}'.format(self._ruleIndex))
    
    print('IPs: {}, len: {}, firewall index: {}, IP: {}'.format(len(self._ips), len(ipList), self._ruleIndex, ip))
    
    cmd = None
    if len(self._ips) == 1:
      cmd = 'netsh advfirewall firewall add rule name="Bitvise SSH Blacklist {0}" dir=in action=block remoteip="{1}"'
    else:
      cmd = 'netsh advfirewall firewall set rule name="Bitvise SSH Blacklist {0}" new remoteip="{1}"'
    cmd = cmd.format(self._ruleIndex, ipList)
    #print('test mode:', cmd)
    out = os.popen(cmd).read().strip(' \n')
    print(out)


class XmlHandler(sax.ContentHandler):
  def __init__(self, fileHandler):
    super().__init__()
    
    self._fileHandler = fileHandler
    
    self._stack = []
    self._event = None
    self._firewallHandler = FirewallHandler()
    self._skip = False
  
  def skip(self, flag):
    self._skip = flag
  
  def startElement(self, tag, attr):
    if tag == 'event':
      self._event = {
        'tag': tag,
        'attr': attr,
      }
    
    self._stack.append((tag, attr))
  
  def endElement(self, tag):
    assert tag == self._stack[-1][0], 'tag mismatch: {} <> {}'.format(self._stack[-1][0], tag)
    
    _, attr = self._stack.pop()
    
    if tag == 'end':
      if attr['reason'] == 'Rollover':
        self._fileHandler.rollover(attr['rolloverToFile'])
        return
      print('Server stopped, exiting:', attr['reason'])
      self._fileHandler.shutdown()
    
    if self._skip:
      return
    
    if self._event and tag in ['session', 'parameters']:
      self._event[tag] = attr
      return
    
    if tag == 'event':
      if self._event['attr']['name'] == 'I_CONNECT_CANCELED' and self._event['parameters']['cancelReason'] == 'ClientVersionNotPermitted':
        self._firewallHandler.add(self._event['session']['remoteAddress'].split(':')[0])
      return


class FileHandler:
  def __init__(self, path):
    self._rollover = None
    self._shutdown = False
    
    self._xmlHandler = XmlHandler(self)
    
    self._parser = sax.make_parser(['sax.IncrementalParser'])
    self._parser.setFeature(sax.handler.feature_namespaces, 0)
    self._parser.setContentHandler(self._xmlHandler)
    
    file = None
    when = 0
    for item in path.iterdir():
      if not item.is_dir():
        item_when = item.stat().st_mtime_ns
        if file and item_when > when:
          file = item
          when = item_when
        else:
          file = item
    
    self._fh = file.open(encoding='utf-8-sig')
    self.loop(True)
  
  def loop(self, skip=False):
    if skip:
      self._xmlHandler.skip(True)
      print('Skipping...')
    else:
      print('Watching...')
    
    while True:
      if self._shutdown:
        self._fh.close()
        return
      
      if self._rollover:
        print('Switching to:', self._rollover)
        self._parser.feed(self._fh.read())
        self._parser.close()
        self._parser.reset()
        self._fh.close()
        self._fh = self._rollover.open(encoding='utf-8-sig')
        self._rollover = None
      
      offset = self._fh.tell()
      line = self._fh.readline()
      
      if '</log>' in line:
        self._fh.seek(offset)
        if skip:
          self._xmlHandler.skip(False)
          return
        sleep(1)
        continue
      
      self._parser.feed(line)
  
  def shutdown(self):
    self._shutdown = True
  
  def rollover(self, file):
    self._rollover = Path(file)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
    'directory', 
    nargs='?',
    default=r'C:\Program Files\Bitvise SSH Server\Logs',
    help='The Bitvise SSH Server log directory.'
  )
  
  args = parser.parse_args()
  logPath = Path(args.directory)
  
  if not logPath.exists() or not logPath.is_dir():
    print('Invalid Bitvise SSH Server log directory path: "{}"'.format(logPath), file=sys.stderr)
    parser.print_help()
    exit(1)
  
  fileHandler = FileHandler(logPath)
  fileHandler.loop()
  
  exit(0)


if __name__ == "__main__":
  main()
