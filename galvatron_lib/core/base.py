from __future__ import print_function

__author__    = 'Mike West'
__email__     = 'mwest67@gmail.com'

import errno
import imp
import json
import os
import random
import re
import shutil
import sys
import builtins
import tempfile

# import framework libs
from galvatron_lib.core import framework

# set the __version__ variable based on the VERSION file
exec(open(os.path.join(sys.path[0], 'VERSION')).read())

# using stdout to spool causes tab complete issues
# therefore, override print function
# use a lock for thread safe console and spool output
from threading import Lock
_print_lock = Lock()
# spooling system
def spool_print(*args, **kwargs):
    with _print_lock:
        if framework.Framework._spool:
            framework.Framework._spool.write('%s\n' % (args[0]))
            framework.Framework._spool.flush()
        if 'console' in kwargs and kwargs['console'] is False:
            return
        # new print function must still use the old print function via the backup
        builtins._print(*args, **kwargs)
# make a builtin backup of the original print function
builtins._print = print
# override the builtin print function with the new print function
builtins.print = spool_print

KEY_RESOURCES = [
    'virus_total_api',
]

#=================================================
# BASE CLASS
#=================================================

class Recon(framework.Framework):

    def __init__(self, mode):
        framework.Framework.__init__(self, 'base')
        self._mode = mode
        self._name = 'galvatron'
        self._prompt_template = '%s[%s] > '
        self._base_prompt = self._prompt_template % ('', self._name)
        # establish dynamic paths for framework elements
        self.app_path = framework.Framework.app_path = sys.path[0]
        self.data_path = framework.Framework.data_path = os.path.join(self.app_path, 'data')
        self.core_path = framework.Framework.core_path = os.path.join(self.app_path, 'core')
        self.options = self._global_options
        self._init_global_options()
        self._init_home()
        self.init_workspace('default')
        if self._mode == Mode.WEB:
          self.use_rawinput = False

        if self._mode == Mode.CONSOLE or self._mode == Mode.WEB:
            self.show_banner()
        self.analytics = False

    #==================================================
    # SUPPORT METHODS
    #==================================================

    def version_check(self):
        return True

    def _send_analytics(self, cd):
        pass

    def _init_global_options(self):
        self.register_option('nameserver', '8.8.8.8', True, 'nameserver for DNS interrogation')
        self.register_option('proxy', None, False, 'proxy server (address:port)')
        self.register_option('threads', 10, True, 'number of threads (where applicable)')
        self.register_option('timeout', 10, True, 'socket timeout (seconds)')
        self.register_option('user-agent', 'galvatron/v%s' % (__version__.split('.')[0]), True, 'user-agent string')
        self.register_option('verbosity', 1, True, 'verbosity level (0 = minimal, 1 = verbose, 2 = debug)')

    def _init_home(self):
        self._home = framework.Framework._home = os.path.join(os.path.expanduser('~'), '.galvatron')
        # initialize home folder
        if not os.path.exists(self._home):
            os.makedirs(self._home)

        # initialize keys database
        self._query_keys('CREATE TABLE IF NOT EXISTS keys (name TEXT PRIMARY KEY, value TEXT)')
        # populate key names
        for name in KEY_RESOURCES:
            self._query_keys('INSERT OR IGNORE INTO keys (name) VALUES (?)', (name,))
        # migrate keys from old .dat file
        key_path = os.path.join(self._home, 'keys.dat')
        if os.path.exists(key_path):
            try:
                key_data = json.loads(open(key_path, 'rb').read())
                for key in key_data:
                    self.add_key(key, key_data[key])
                os.remove(key_path)
            except:
                self.error('Corrupt key file. Manual migration required.')

    def _load_modules(self):
        self.loaded_category = {}
        self._loaded_modules = framework.Framework._loaded_modules
        # crawl the module directory and build the module tree
        for path in [os.path.join(x, 'modules') for x in (self.app_path, self._home)]:
            for dirpath, dirnames, filenames in os.walk(path):
                # remove hidden files and directories
                filenames = [f for f in filenames if not f[0] == '.']
                dirnames[:] = [d for d in dirnames if not d[0] == '.']
                if len(filenames) > 0:
                    for filename in [f for f in filenames if f.endswith('.py')]:
                        is_loaded = self._load_module(dirpath, filename)
                        mod_category = 'disabled'
                        if is_loaded:
                            mod_category = dirpath.split(os.sep)[-1]
                            #mod_category = re.search('/modules/([^/]*)', dirpath).group(1)
                        # store the resulting category statistics
                        if not mod_category in self.loaded_category:
                            self.loaded_category[mod_category] = 0
                        self.loaded_category[mod_category] += 1

    def _load_module(self, dirpath, filename):
        mod_name = filename.split('.')[0]
        mod_dispname = '/'.join(re.split('modules', dirpath)[-1].strip(os.sep).split(os.sep) + [mod_name])
        mod_loadname = mod_dispname.replace('/', '_')
        mod_loadpath = os.path.join(dirpath, filename)
        mod_file = open(mod_loadpath)
        try:
            # import the module into memory
            mod = imp.load_source(mod_loadname, mod_loadpath, mod_file)
            __import__(mod_loadname)
            # add the module to the framework's loaded modules
            self._loaded_modules[mod_dispname] = sys.modules[mod_loadname].Module(mod_dispname)
            if self._mode == Mode.WEB:
              self._loaded_modules[mod_dispname].use_rawinput = False
            return True
        except ImportError as e:
            # notify the user of missing dependencies
            self.error('Module \'%s\' disabled. Dependency required: \'%s\'' % (mod_dispname, e))
        except:
            # notify the user of errors
            self.print_exception()
            self.error('Module \'%s\' disabled.' % (mod_dispname))
        # remove the module from the framework's loaded modules
        self._loaded_modules.pop(mod_dispname, None)
        return False

    def _menu_egg(self, params):
        eggs = [
                'Really? A menu option? Try again.',
                'You clearly need \'help\'.',
                'That makes no sense to me.',
                '*grunt* *grunt* Nope. I got nothin\'.',
                'Wait for it...',
                'This is not the Social Engineering Toolkit.',
                'Don\'t you think if that worked the numbers would at least be in order?',
                'Reserving that option for the next-NEXT generation of the framework.',
                'You\'ve clearly got the wrong framework. Attempting to start SET...',
                'Your mother called. She wants her menu driven UI back.',
                'What\'s the samurai password?'
                ]
        print(random.choice(eggs))
        return

    #==================================================
    # WORKSPACE METHODS
    #==================================================

    def init_workspace(self, workspace):
        workspace = os.path.join(self._home, 'workspaces', workspace)
        new = False
        try:
            os.makedirs(workspace)
            new = True
        except OSError as e:
            if e.errno != errno.EEXIST:
                self.error(e.__str__())
                return False
        # set workspace attributes
        self.workspace = framework.Framework.workspace = workspace
        self.prompt = self._prompt_template % (self._base_prompt[:-3], self.workspace.split(os.sep)[-1])
        # configure new database or conduct migrations
        self._create_db() if new else self._migrate_db()
        # load workspace configuration
        self._init_global_options()
        self._load_config()
        # load modules after config to populate options
        self._load_modules()
        return True

    def delete_workspace(self, workspace):
        path = os.path.join(self._home, 'workspaces', workspace)
        try:
            shutil.rmtree(path)
        except OSError:
            return False
        if workspace == self.workspace.split(os.sep)[-1]:
            self.init_workspace('default')
        return True

    def _get_workspaces(self):
        dirnames = []
        path = os.path.join(self._home, 'workspaces')
        for name in os.listdir(path):
            if os.path.isdir(os.path.join(path, name)):
                dirnames.append(name)
        return dirnames

    def _get_snapshots(self):
        snapshots = []
        for f in os.listdir(self.workspace):
            if re.search('^snapshot_\d{14}.db$', f):
                snapshots.append(f)
        return snapshots

    def _create_db(self):
        self.query('CREATE TABLE IF NOT EXISTS targets (location TEXT, vendor TEXT, product_name TEXT, version TEXT, extracted_location TEXT, sandbox_id TEXT, original_location TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS cve (product TEXT, version TEXT, cve_number TEXT, description TEXT, published TEXT, cvss TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS virus_scan (product TEXT, version TEXT, engine TEXT, engine_version TEXT, update_version TEXT, description TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS qa_issue (product TEXT, version TEXT, file_name TEXT, location TEXT, line_number TEXT, description TEXT, note TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS url (product TEXT, version TEXT, method TEXT, url TEXT, data TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS dashboard (module TEXT PRIMARY KEY, runs INT)')
        self.query('CREATE TABLE IF NOT EXISTS sandbox_result (product TEXT, version TEXT, description TEXT, severity TEXT, module TEXT)')
        self.query('CREATE TABLE IF NOT EXISTS reported_change (product TEXT, version TEXT, object_type TEXT, action TEXT, change_data TEXT, module TEXT)')
        self.query('PRAGMA user_version = 8')

    def _migrate_db(self):
        db_version = lambda self: self.query('PRAGMA user_version')[0][0]
        if db_version(self) == 0:
            # add mname column to contacts table
            tmp = self.get_random_str(20)
            self.query('ALTER TABLE contacts RENAME TO %s' % (tmp))
            self.query('CREATE TABLE contacts (fname TEXT, mname TEXT, lname TEXT, email TEXT, title TEXT, region TEXT, country TEXT)')
            self.query('INSERT INTO contacts (fname, lname, email, title, region, country) SELECT fname, lname, email, title, region, country FROM %s' % (tmp))
            self.query('DROP TABLE %s' % (tmp))
            self.query('PRAGMA user_version = 1')
        if db_version(self) == 1:
            # rename name columns
            tmp = self.get_random_str(20)
            self.query('ALTER TABLE contacts RENAME TO %s' % (tmp))
            self.query('CREATE TABLE contacts (first_name TEXT, middle_name TEXT, last_name TEXT, email TEXT, title TEXT, region TEXT, country TEXT)')
            self.query('INSERT INTO contacts (first_name, middle_name, last_name, email, title, region, country) SELECT fname, mname, lname, email, title, region, country FROM %s' % (tmp))
            self.query('DROP TABLE %s' % (tmp))
            # rename pushpin table
            self.query('ALTER TABLE pushpin RENAME TO pushpins')
            # add new tables
            self.query('CREATE TABLE IF NOT EXISTS domains (domain TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS companies (company TEXT, description TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS netblocks (netblock TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS locations (latitude TEXT, longitude TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS vulnerabilities (host TEXT, reference TEXT, example TEXT, publish_date TEXT, category TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS ports (ip_address TEXT, host TEXT, port TEXT, protocol TEXT)')
            self.query('CREATE TABLE IF NOT EXISTS leaks (leak_id TEXT, description TEXT, source_refs TEXT, leak_type TEXT, title TEXT, import_date TEXT, leak_date TEXT, attackers TEXT, num_entries TEXT, score TEXT, num_domains_affected TEXT, attack_method TEXT, target_industries TEXT, password_hash TEXT, targets TEXT, media_refs TEXT)')
            self.query('PRAGMA user_version = 2')
        if db_version(self) == 2:
            # add street_address column to locations table
            self.query('ALTER TABLE locations ADD COLUMN street_address TEXT')
            self.query('PRAGMA user_version = 3')
        if db_version(self) == 3:
            # account for db_version bug
            if 'creds' in self.get_tables():
                # rename creds table
                self.query('ALTER TABLE creds RENAME TO credentials')
            self.query('PRAGMA user_version = 4')
        if db_version(self) == 4:
            # add status column to vulnerabilities table
            if 'status' not in [x[0] for x in self.get_columns('vulnerabilities')]:
                self.query('ALTER TABLE vulnerabilities ADD COLUMN status TEXT')
            # add module column to all tables
            for table in ['domains', 'companies', 'netblocks', 'locations', 'vulnerabilities', 'ports', 'hosts', 'contacts', 'credentials', 'leaks', 'pushpins']:
                if 'module' not in [x[0] for x in self.get_columns(table)]:
                    self.query('ALTER TABLE %s ADD COLUMN module TEXT' % (table))
            self.query('PRAGMA user_version = 5')
        if db_version(self) == 5:
            # add profile table
            self.query('CREATE TABLE IF NOT EXISTS profiles (username TEXT, resource TEXT, url TEXT, category TEXT, notes TEXT, module TEXT)')
            self.query('PRAGMA user_version = 6')
        if db_version(self) == 6:
            # add profile table
            self.query('CREATE TABLE IF NOT EXISTS repositories (name TEXT, owner TEXT, description TEXT, resource TEXT, category TEXT, url TEXT, module TEXT)')
            self.query('PRAGMA user_version = 7')
        if db_version(self) == 7:
            # add password_type column to leaks table
            self.query('ALTER TABLE leaks ADD COLUMN password_type TEXT')
            self.query('UPDATE leaks SET password_type=\'unknown\'')
            self.query('PRAGMA user_version = 8')

    #==================================================
    # SHOW METHODS
    #==================================================

    def show_banner(self, *params):
        banner = open(os.path.join(self.data_path, 'banner.txt')).read()
        banner_len = len(max(banner.split('\n'), key=len))
        print(banner)
        print('{0:^{1}}'.format('%s[%s v%s, %s]%s' % (framework.Colors.O, self._name, __version__, __author__, framework.Colors.N), banner_len+8)) # +8 compensates for the color bytes
        print('')
        counts = [(self.loaded_category[x], x) for x in self.loaded_category]
        count_len = len(max([str(x[0]) for x in counts], key=len))
        for count in sorted(counts, reverse=True):
            cnt = '[%d]' % (count[0])
            print('%s%s %s modules%s' % (framework.Colors.B, cnt.ljust(count_len+2), count[1].title(), framework.Colors.N))
            # create dynamic easter egg command based on counts
            setattr(self, 'do_%d' % count[0], self._menu_egg)
        print('')

    def show_workspaces(self, *params):
        self.do_workspaces('list')

    #==================================================
    # COMMAND METHODS
    #==================================================

    def do_reload(self, params):
        '''Reloads all modules'''
        self.output('Reloading...')
        self._load_modules()

    def do_workspaces(self, params):
        '''Manages workspaces'''
        if not params:
            self.help_workspaces()
            return
        params = params.split()
        arg = params.pop(0).lower()
        if arg == 'list':
            self.table([[x] for x in self._get_workspaces()], header=['Workspaces'])
        elif arg in ['add', 'select']:
            if len(params) == 1:
                if not self.init_workspace(params[0]):
                    self.output('Unable to initialize \'%s\' workspace.' % (params[0]))
            else: print('Usage: workspace [add|select] <name>')
        elif arg == 'delete':
            if len(params) == 1:
                if not self.delete_workspace(params[0]):
                    self.output('Unable to delete \'%s\' workspace.' % (params[0]))
            else: print('Usage: workspace delete <name>')
        else:
            self.help_workspaces()

    def do_load(self, params):
        '''Loads specified module'''
        try:
            self._validate_options()
        except framework.FrameworkException as e:
            self.error(e.message)
            return
        if not params:
            self.help_load()
            return
        # finds any modules that contain params
        modules = [params] if params in self._loaded_modules else [x for x in self._loaded_modules if params in x]
        # notify the user if none or multiple modules are found
        if len(modules) != 1:
            if not modules:
                self.error('Invalid module name.')
            else:
                self.output('Multiple modules match \'%s\'.' % params)
                self.show_modules(modules)
            return
        # load the module
        mod_dispname = modules[0]
        # loop to support reload logic
        while True:
            y = self._loaded_modules[mod_dispname]
            # send analytics information
            mod_loadpath = os.path.abspath(sys.modules[y.__module__].__file__)
            if (self._home not in mod_loadpath) and self.analytics:
                self._send_analytics(mod_dispname)
            # return the loaded module if in command line mode
            if self._mode == Mode.CLI:
                return y
            # begin a command loop
            y.prompt = self._prompt_template % (self.prompt[:-3], mod_dispname.split(os.sep)[-1])
            try:
                y.cmdloop()
            except KeyboardInterrupt:
                print('')
            if y._exit == 1:
                return True
            if y._reload == 1:
                self.output('Reloading...')
                # reload the module in memory
                is_loaded = self._load_module(os.path.dirname(mod_loadpath), os.path.basename(mod_loadpath))
                if is_loaded:
                    # reload the module in the framework
                    continue
                # shuffle category counts?
            break
    do_use = do_load

    def do_qa_note(self, params):
        '''Adds a note to a found qa item using the specified editor'''

        if len(params) == 0:
            self.error("Need to pass in a qa issue row id")
            return

        if not "EDITOR" in os.environ:
            self.error("Need to have the EDITOR environment variable set")
            return

        current_note = self.query("SELECT note FROM qa_issue WHERE ROWID = %s" % params)[0][0]

        if current_note == None:
            current_note = ""

        editor = os.environ["EDITOR"]
        handle, name = tempfile.mkstemp(text=True)
        os.close(handle)

        with open(name, "w") as f:
            f.write(current_note)

        os.system("%s %s" % (editor, name))

        with open(name, "r") as f:
            content = f.read()

        content = content.replace("\n", '<br/>')
        os.unlink(name)
        query = "UPDATE qa_issue set note = '%s' where ROWID = %s" % (content, params)
        self.output("Running query: %s" % query)
        self.query(query)


    def help_qa_note(self):
        print(getattr(self, 'do_qa_note').__doc__)
        print('')
        print('Usage: qa_note ROWID')
        print('')


    #==================================================
    # HELP METHODS
    #==================================================

    def help_workspaces(self):
        print(getattr(self, 'do_workspaces').__doc__)
        print('')
        print('Usage: workspaces [list|add|select|delete]')
        print('')

    #==================================================
    # COMPLETE METHODS
    #==================================================

    def complete_workspaces(self, text, line, *ignored):
        args = line.split()
        options = ['list', 'add', 'select', 'delete']
        if 1 < len(args) < 4:
            if args[1].lower() in options[2:]:
                return [x for x in self._get_workspaces() if x.startswith(text)]
            if args[1].lower() in options[:2]:
                return []
        return [x for x in options if x.startswith(text)]

#=================================================
# SUPPORT CLASSES
#=================================================

class Mode(object):
   '''Contains constants that represent the state of the interpreter.'''
   CONSOLE = 0
   CLI     = 1
   GUI     = 2
   WEB     = 3

   def __init__(self):
       raise NotImplementedError('This class should never be instantiated.')
