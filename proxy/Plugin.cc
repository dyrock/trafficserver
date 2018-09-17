/** @file

  Plugin init

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <cstdio>
#include "ts/ink_platform.h"
#include "ts/ink_file.h"
#include "ts/ParseRules.h"
#include "I_RecCore.h"
#include "ts/I_Layout.h"
#include "InkAPIInternal.h"
#include "Main.h"
#include "Plugin.h"
#include "ts/ink_cap.h"

#define MAX_PLUGIN_ARGS 64

static const char *plugin_dir = ".";

using init_func_t = void (*)(int, char **);

int_thread_key PluginContext::THREAD_KEY;
GlobalPluginInfo* PluginManager::Internal_Plugin_Info;
GlobalPluginInfo* PluginManager::Default_Plugin_Info;

PluginManager pluginManager;

// Plugin registration vars
//
//    plugin_reg_list has an entry for each plugin
//      we've successfully been able to load
//    plugin_reg_current is used to associate the
//      plugin we're in the process of loading with
//      it struct.  We need this global pointer since
//      the API doesn't have any plugin context.  Init
//      is single threaded so we can get away with the
//      global pointer
//
DLL<PluginRegInfo> plugin_reg_list;

PluginInfo::PluginInfo() : _magic(MAGIC), dlh(nullptr)
{
  _flags._all = 0;
}

PluginInfo::~PluginInfo()
{
  // We don't support unloading plugins once they are successfully loaded, so assert
  // that we don't accidentally attempt this.
  ink_release_assert(!this->_flags._flag._registered == false);
  ink_release_assert(this->link.prev == nullptr);
  if (dlh)
    dlclose(dlh);
}

PluginManager::PluginManager()
{
  ink_thread_key_create(&PluginContext::THREAD_KEY, nullptr);
  ink_thread_setspecific(PluginContext::THREAD_KEY, nullptr);
  // TS uses plugin mechanisms in various places and so needs a valid plugin info block
  // for them. This needs to be very early because threads get started before
  // PluginManager::init is called. This data is all effectively static so it can be done
  // earlier than configuration for actual plugins.
  Internal_Plugin_Info = new GlobalPluginInfo;
  Internal_Plugin_Info->_name = ats_strdup("TrafficServer Internal");
  Internal_Plugin_Info->_vendor = ats_strdup("Apache Software Foundation");
  Internal_Plugin_Info->_file_path = ats_strdup(".");
  Internal_Plugin_Info->_email = ats_strdup("dev@trafficserver.apache.org");

  // For instances where real plugin info isn't available for various reasons.
  Default_Plugin_Info = new GlobalPluginInfo;
  Default_Plugin_Info->_name = ats_strdup("TrafficServer Default");
  Default_Plugin_Info->_vendor = ats_strdup("Apache Software Foundation");
  Default_Plugin_Info->_file_path = ats_strdup(".");
  Default_Plugin_Info->_email = ats_strdup("dev@trafficserver.apache.org");
}

bool
PluginManager::load(int argc, char *argv[], bool continueOnError)
{
  char path[PATH_NAME_MAX];
  init_func_t init;
  PluginInfo* info = nullptr;

  if (argc < 1) {
    return true;
  }
  ink_filepath_make(path, sizeof(path), plugin_dir, argv[0]);

  Note("loading plugin '%s'", path);

  for (PluginInfo *plugin_reg_temp = plugin_reg_list.head; plugin_reg_temp != nullptr;
       plugin_reg_temp                = (plugin_reg_temp->link).next) {
    if (strcmp(plugin_reg_temp->_file_path, path) == 0) {
      Warning("multiple loading of plugin %s", path);
      break;
    }
  }

  // elevate the access to read files as root if compiled with capabilities, if not
  // change the effective user to root
  {
    uint32_t elevate_access = 0;
    REC_ReadConfigInteger(elevate_access, "proxy.config.plugin.load_elevated");
    ElevateAccess access(elevate_access ? ElevateAccess::FILE_PRIVILEGE : 0);

    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
      if (!continueOnError) {
        Fatal("unable to load '%s': %s", path, dlerror());
        return false;
      }
    }

    // Allocate a new registration structure for the
    //    plugin we're starting up
    info = new GlobalPluginInfo;
    info->_file_path = ats_strdup(path);
    info->dlh = handle;

    init = reinterpret_cast<init_func_t>(dlsym(plugin_reg_current->dlh, "TSPluginInit"));

    if (!init) {
      delete info;
      if (!continueOnError) {
        Fatal("unable to find TSPluginInit function in '%s': %s", path, dlerror());
        return false;
      }
      return false; // this line won't get called since Fatal brings down ATS
    }

#if defined(freebsd) || defined(darwin)
    optreset = 1;
#endif
#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
#endif
    opterr = 0;
    optarg = nullptr;

    {
      PluginContext pc(info);
      init(argc, argv);
    }

  } // done elevating access

  if (info->_flags._flag._registered) {
    plugin_reg_list.push(info);
  } else {
    Fatal("plugin not registered by calling TSPluginRegister");
    return false; // this line won't get called since Fatal brings down ATS
  }

  return true;
}

static char *
PluginManager::expand(char *arg)
{
  RecDataT data_type;
  char *str = nullptr;

  if (*arg != '$') {
    return nullptr;
  }
  // skip the $ character
  arg += 1;

  if (RecGetRecordDataType(arg, &data_type) == REC_ERR_OKAY) {
    switch (data_type) {
      case RECD_STRING: {
        RecString str_val;
        if (RecGetRecordString_Xmalloc(arg, &str_val) == REC_ERR_OKAY) {
          return static_cast<char*>(str_val);
        }
        break;
      }
      case RECD_FLOAT: {
        RecFloat float_val;
        if (RecGetRecordFloat(arg, &float_val) == REC_ERR_OKAY) {
          str = static_cast<char*>(ats_malloc(128));
          snprintf(str, 128, "%F", (float)float_val);
          return str;
        }
        break;
      }
      case RECD_INT: {
        RecInt int_val;
        if (RecGetRecordInt(arg, &int_val) == REC_ERR_OKAY) {
          str = static_cast<char*>(ats_malloc(128));
          snprintf(str, 128, "%ld", (long int)int_val);
          return str;
        }
        break;
      }
      case RECD_COUNTER: {
        RecCounter count_val;
        if (RecGetRecordCounter(arg, &count_val) == REC_ERR_OKAY) {
          str = static_cast<char*>(ats_malloc(128));
          snprintf(str, 128, "%ld", (long int)count_val);
          return str;
        }
        break;
      }
      default:
        break;
    }
  }
  Warning("plugin.config: unable to find parameter %s", arg);
  return nullptr;
}

void
PluginManager::initForThread()
{
  PluginContext::setDefaultPluginInfo(Default_Plugin_Info);
  Debug("plugin", "Plugin Context %p for thread %p [%" PRIx64 "]\n", Default_Plugin_Info, this_ethread(), this_ethread()->tid);
}

bool
PluginManager::init(bool continueOnError)
{
  ats_scoped_str path;
  char line[1024], *p;
  char *argv[MAX_PLUGIN_ARGS];
  char *vars[MAX_PLUGIN_ARGS];
  int argc;
  int fd;
  int i;
  bool retVal           = true;
  static bool INIT_ONCE = true;

  if (INIT_ONCE) {
    api_init();
    plugin_dir = ats_stringdup(RecConfigReadPluginDir());
    INIT_ONCE  = false;
  }

  path = RecConfigReadConfigPath(nullptr, "plugin.config");
  fd   = open(path, O_RDONLY);
  if (fd < 0) {
    Warning("unable to open plugin config file '%s': %d, %s", (const char *)path, errno, strerror(errno));
    return false;
  }

  while (ink_file_fd_readline(fd, sizeof(line) - 1, line) > 0) {
    argc = 0;
    p    = line;

    // strip leading white space and test for comment or blank line
    while (*p && ParseRules::is_wslfcr(*p)) {
      ++p;
    }
    if ((*p == '\0') || (*p == '#')) {
      continue;
    }

    // not comment or blank, so rip line into tokens
    while (true) {
      if (argc >= MAX_PLUGIN_ARGS) {
        Warning("Exceeded max number of args (%d) for plugin: [%s]", MAX_PLUGIN_ARGS, argc > 0 ? argv[0] : "???");
        break;
      }

      while (*p && ParseRules::is_wslfcr(*p)) {
        ++p;
      }
      if ((*p == '\0') || (*p == '#')) {
        break; // EOL
      }

      if (*p == '\"') {
        p += 1;

        argv[argc++] = p;

        while (*p && (*p != '\"')) {
          p += 1;
        }
        if (*p == '\0') {
          break;
        }
        *p++ = '\0';
      } else {
        argv[argc++] = p;

        while (*p && !ParseRules::is_wslfcr(*p) && (*p != '#')) {
          p += 1;
        }
        if ((*p == '\0') || (*p == '#')) {
          break;
        }
        *p++ = '\0';
      }
    }

    for (i = 0; i < argc; i++) {
      vars[i] = this->expand(argv[i]);
      if (vars[i]) {
        argv[i] = vars[i];
      }
    }

    if (argc < MAX_PLUGIN_ARGS) {
      argv[argc] = nullptr;
    } else {
      argv[MAX_PLUGIN_ARGS - 1] = nullptr;
    }
    retVal = this->load(argc, argv, continueOnError);

    for (i = 0; i < argc; i++) {
      ats_free(vars[i]);
    }
  }

  close(fd);

  // Notification that plugin loading has finished
  APIHook *hook = lifecycle_hooks->get(TS_LIFECYCLE_PLUGINS_LOADED_HOOK);
  while (hook) {
    hook->invoke(TS_EVENT_LIFECYCLE_PLUGINS_LOADED, nullptr);
    hook = hook->next();
  }

  return retVal;
}

PluginInfo const*
PluginManager::find(char const* name)
{
  for (PluginInfo* pi = plugin_reg_list.head; nullptr != pi; pi = pi->link.next) {
    if (0 == strcasecmp(name, pi->_name))
      return pi;
  }
  return nullptr;
}
