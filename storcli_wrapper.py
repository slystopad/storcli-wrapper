#!/usr/bin/env python
import os
import sys
import argparse
import json
import subprocess

FAKE_STORCLI_OUT={'call':'tests/input_call.json',
                  'call_dall':'tests/input_call_dall.json',
                  'call_eall_sall':'tests/input_call_eall_sall.json'}

PD_STATES = ['onln', 'ugood', 'ubad', 'msng']
VD_STATES = ['optl', 'dgrd']
STORCLI_PATH = ['/opt/MegaRAID/storcli']
STORCLI_BIN_NAME = 'storcli64'

def get_drives(fakeinput=FAKE_STORCLI_OUT['call_eall_sall']):
    with open(fakeinput, 'r') as f:
        data = json.load(f)
    return data

# https://gist.github.com/SEJeff/2576984
def find_binary(exe=None):
    '''
    Looks for file and return it's path
    '''
    if exe:
        (path, name) = os.path.split(exe)
        if os.access(exe, os.X_OK):
            return os.path.realpath(exe)
        for path in STORCLI_PATH + os.environ.get('PATH').split(os.pathsep):
            full_path = os.path.join(path, exe)
            if os.access(full_path, os.X_OK):
                return full_path
    raise RuntimeError('Can not find StorCLI binary `{}`'.format(exe))

def get_data():
    cmd = find_binary(STORCLI_BIN_NAME)
    data = subprocess.check_output(
        [cmd, "/call show J"],
        stderr=subprocess.STDOUT)
    return data

def apply_tf(data, tf):
    """Apply function `tf` (transformation function) if specified
    and return result. Return unmodified data in other case"""
    if tf:
      return tf(data)
    else:
      return data

def get_filtered(data, rules={}):
    """Filters out or modifies keys/values of dict
       
       Args:
         data (dict): dict to modify
         rules (dict): dict of rule 2-tuples
       
       Returns:
         dict: modified dict if rules is specified
         dict: original dict if rules is not specified
    """
    if (len(rules) == 0) or (len(data) == 0):
        return data
    
    result = {}
    for oldname in data:
        ## if oldname does not have corresponding rule, drop it from result
        if oldname not in rules: 
            continue
        ## get rule to apply
        rule = rules[oldname]
        ## rule 'schema' verification
        if len(rule) < 2:
            raise ValueError('Wrong rule format. rule={}'.format(rule))
        ## new name for key has been specified in rule
        newname, tf = rule
        ## change old key name to new key name and apply tranformation function
        if newname:
            result[newname] = apply_tf(data[oldname], tf)
        else:
            result[oldname] = apply_tf(data[oldname], tf)
    return result

def remap_to_int(value, mapping_list):
    """Change value to it's int equivalent
    Args:
      value (str):
      mapping_list (list):

    Returns special value 65534 if value is absent in mapping_list
    It should be considered as indicator to update provided mappings
    If you receive 65534 please open bug and provide example of
    storcli output
    """
    try:
        return mapping_list.index(value.lower())
    except ValueError:
        return 65534

def pd_states(value):
    return remap_to_int(value, PD_STATES)

def vd_states(value):
    return remap_to_int(value, VD_STATES)

def rstrip(string):
    return string.rstrip()

PD_FILTER_RULES = {'DID': (None, str),
                   'State': ('state', pd_states),
                   'DG' : (None, str),
                   'Size': ('size', None),
                   'Model': ('model', rstrip)}

VD_FILTER_RULES = {'DG/VD': ('DG_VD', None),
                   'State': ('state', vd_states),
                   'Size': ('size', None),
                   'TYPE': (None, None)}

TELEGRAF_CONF = '''
  
[[inputs.exec]]
  commands = [
    "{progname} --vd-list",
    "{progname} --pd-list"
  ]

  data_format = "json"

  tag_keys = {tag_keys}
'''

def get_sample_telegraf_conf(progname):
    """Generates example config for Telegraf
    to use this tool with `inputs.exec` module
    """
    pd_tags = to_pretty_json(PD_FILTER_RULES)
    vd_tags = to_pretty_json(VD_FILTER_RULES)
    both = to_pretty_json(PD_FILTER_RULES.keys()
                          + VD_FILTER_RULES.keys())
    print '#'*79
    print '  Physical Drives tag_keys:'
    print '#'*79
    print 'tag_keys = {}'.format(pd_tags)
    print
    print '#'*79
    print '  Virtual Drives tag_keys:'
    print '#'*79
    print 'tag_keys = {}'.format(vd_tags)
    print
    print '#'*79
    print '  For both:'
    print '#'*79
    print 'tag_keys = {}'.format(both)
    print
    print '#'*79
    print '  Telegraf config:'
    print '#'*79
    ## dirty way to add identation to last line of preatty json string
    print TELEGRAF_CONF.format(progname=progname, tag_keys=both[:-1]+'  ]')

def to_pretty_json(value):
    """Returns preatty json list"""
    if type(value) == list:
        return json.dumps(value, indent=4, sort_keys=True)
    elif type(value) == dict:
        return json.dumps(value.keys(), indent=4, sort_keys=True)
    else: 
        raise ValueError('Only `list` or `dict` are allowed')
                

class StorcliBaseWrapper(object):
  """TODO """
  _cmd_status = {}
  _pd_list = {}
  _vd_list = {}
  _pd_count = {}
  _vd_count = {}
  _missing_count = {}
  _PD_FILTER_RULES = PD_FILTER_RULES
  _VD_FILTER_RULES = VD_FILTER_RULES

  def __init__(self, filename=None):
    """ TODO """
    if filename:
        with open(filename, 'r') as f:
            self._data = json.load(f)
    else:
        self._data = json.loads(get_data())

    controllers = self._data.get('Controllers')
    for ctl in controllers:
      ctl_id = ctl.get('Command Status').get('Controller')
      self._cmd_status[ctl_id] = ctl.get('Command Status', {}).get('Status')
      err = ctl.get('Command Status', {}).get('Description')
      if self._cmd_status[ctl_id] != 'Success':
          raise RuntimeError(err)
      self._pd_list[ctl_id] = ctl.get('Response Data', {}).get('PD LIST')
      self._vd_list[ctl_id] = ctl.get('Response Data', {}).get('VD LIST')
      self._pd_count[ctl_id] = ctl.get('Response Data', {}).get('Physical Drives')
      self._vd_count[ctl_id] = ctl.get('Response Data', {}).get('Virtual Drives')
      self._missing_count[ctl_id] = ctl.get('Response Data', {}).get('Missing Drives Count', 0)

  @property
  def pd(self, ctl=0):
    result = [ get_filtered(pd, self._PD_FILTER_RULES) for pd in self.raw_pd ]
    return json.dumps(result)

  @property
  def raw_pd(self, ctl=0):
    return self._pd_list[ctl]

  @property
  def vd(self, ctl=0):
    result = [ get_filtered(vd, self._VD_FILTER_RULES) for vd in self.raw_vd ]
    return json.dumps(result)

  @property
  def raw_vd(self, ctl=0):
    return self._vd_list[ctl]

  @property
  def pd_count(self, ctl=0):
    return json.dumps(int(self._pd_count[ctl]))

  @property
  def raw_pd_count(self, ctl=0):
    return int(self._pd_count[ctl])

  @property
  def vd_count(self, ctl=0):
    return json.dumps(int(self._vd_count[ctl]))

  @property
  def raw_vd_count(self, ctl=0):
    return int(self._vd_count[ctl])

  @property
  def missing_count(self, ctl=0):
    result = {'pd_missing': int(self._missing_count[ctl])}
    return json.dumps(result)

  @property
  def raw_missing_count(self, ctl=0):
    return int(self._missing_count[ctl])

def get_cli_options():
  """ Parse CLI options and return """
  parser = argparse.ArgumentParser(description='Parser for LSI Storage Command Line Tool',
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   epilog=HELP_EPILOG)
  group = parser.add_mutually_exclusive_group()
  group.add_argument('--pd-list', action='store_true',
                      help="Get status of Physical Drives (default mode)")
  group.add_argument('--vd-list', action='store_true',
                      help="Get status of Virtual Drives")
  group.add_argument('--pd-count', action='store_true',
                      help="Get number of Physical Drives")
  group.add_argument('--vd-count', action='store_true',
                      help="Get number of Virtual Drives")
  group.add_argument('--missing-count', action='store_true',
                      help="Get number of Missing(failed) drives")
  group.add_argument('--sample-config', action='store_true',
                      help="Show example config for Telegraf")
  parser.add_argument('--file',
                      help="JSON file to get data from file instead of "
                           + "getting it from controller. "
                           + "Usually you don't need this option")

  args = parser.parse_args()
  return (args, parser.prog)

HELP_EPILOG = '''
  The tool is simple wrapper around Storage Command Line Tool.
  It is intended to be run by Telegraf `exec` input module
  to collect metrics for Physical Drives (PD) and
  Virtual Drives (VD/RAID arrays) connected to LSI controllers
  known to Storage Command Line Tool (StorCLI). Actually it works
  as simple filter to normalize data it gets from StorCLI.
  It run StorCLI utility to get data from controller.
  The tool looks for StorCLI binary in the following directories:
    current directory
    /opt/MegaRAID/storcli
    $PATH 

  Tested with folowing RAID controllers:
    LSI 3108 MegaRAID
    Cisco 12G SAS Modular Raid Controller
  and
    Storage Command Line Tool Ver 1.03.11 Jan 30, 2013
    Storage Command Line Tool Ver 007.0205.0000.0000 March 27, 2017

  Links:
    Telegraf https://docs.influxdata.com/telegraf/
    StorCLI https://www.broadcom.com/support/download-search
            (search by `storcli`)

  Limitations:
    only one controller is supported at the time
    --sample-config is broken
    must be run via `sudo`

    If you receive 65534 as disk state please open bug and provide
    example of storcli output
'''

if __name__ == "__main__":
  args, progname = get_cli_options()

  if args.sample_config:
    get_sample_telegraf_conf(progname)
    sys.exit(0)

  try:
    if args.file:
      res = StorcliBaseWrapper(args.file)
    else:
      res = StorcliBaseWrapper()
  except Exception, e:
    sys.exit(e)

  if args.pd_count:
    print res.pd_count
  elif args.vd_count:
    print res.vd_count
  elif args.missing_count:
    print res.missing_count
  elif args.vd_list:
    print res.vd
  elif args.pd_list:
    print res.pd
  else:
    print res.pd

  sys.exit(0)
