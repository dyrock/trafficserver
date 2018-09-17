/** @file

  Plugin init declarations

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

#pragma once

#include "ts/List.h"

struct PluginInfo {
  enum { MAGIC = 0xabacab56 };
  PluginInfo();
  // Subclasses will get stored in lists as this base class so make sure their
  // destructors are accessible.
  virtual ~PluginInfo();

  /// Path to the implementation (library, so, dll) file.
  ats_scoped_str _file_path;
  /// Name of the plugin.
  ats_scoped_str _name;

  uint64_t magic; ///< Standard magic value for validity checks.

  /// Library handle
  void *dlh;

  /// Status flags
  union {
    unsigned int _all : 32;
    struct {
      unsigned int _registered : 1;
      unsigned int _disabled : 1;
    } _flag;
  } _flags;

  /// For the overall registration list.
  LINK(PluginRegInfo, link);
};

struct GlobalPluginInfo : public PluginInfo {
  /// Plugin vendor name.
  ats_scoped_str _vendor;
  /// Email for vendor/author.
  ats_scoped_str _email;
};

/** Manage the set of plugins.
 */
class PluginManager
{
public:
  PluginManager();

  /// Initialize all the plugins.
  bool init(bool continueOnError = false);
  /// Expand argument to plugin.
  char *expand(char *);

  /// Locate a plugin by @a name.
  PluginInfo const *find(char const *name);

  /// Used for plugin type continuations created and used by TS itself.
  static GlobalPluginInfo *Internal_Plugin_Info;

  /// Used primarily for remap plugins which are not required to register.
  static GlobalPluginInfo *Default_Plugin_Info;

  /// Initialize thread local storage needed for plugin management.
  void initForThread();

protected:
  /// Load a single plugin
  bool load(int arg, char *argv[], bool continueOnError);
}

/// Globally accessible singleton.
extern PluginManager pluginManager;

/** Control and access a per thread plugin context.

    This should be used to set the context when a plugin callback is invoked.
    Static methods can be used to get the current plugin.
*/
class PluginContext
{
public:
  /// Set the plugin context in a scoped fashion.
  /// This is re-entrant.
  PluginContext(PluginInfo const *plugin)
  {
    _save = ink_thread_getspecific(THREAD_KEY);
    // Unfortunately thread local storage won't preserve const
    ink_thread_set_specific(THREAD_KEY, const_cast<PluginInfo *>(plugin));
  }

  ~PluginContext()
  {
    ink_thread_setspecific(THREAD_KEY, _save);
  }

  /// Get the current plugin in context.
  /// @return the plugin info or @c nullptr if there is no plugin context.
  static PluginInfo const *
  get()
  {
    return static_cast<PluginInfo const*>(ink_thread_getspecific(THREAD_KEY));
  }

private:
  /// Set a default plugin context if none in play.
  /// @internal This is used to set the internal plugin info as the default so
  /// that it is used when hook calls are made from core code. This needs to be
  /// called on each thread once (when the thread starts).
  static void
  setDefaultPluginInfo(PluginInfo const *p)
  {
    ink_thread_setspecific(THREAD_KEY, const_cast<PluginInfo *>(p));
  }

  void *_save; ///< Value to restore when context goes out of scope.

  /// The key for the per thread context. This is initialized by the @c PluginManager
  /// singleton.
  static ink_thread_key THREAD_KEY;

  friend class PluginManager;
}
/** Abstract interface class for plugin based continuations.

    The primary intended use of this is for logging so that continuations
    that generate logging messages can generate plugin local data in a
    generic way.

    The core will at appropriate times dynamically cast the continuation
    to this class and if successful access the plugin data via these
    methods.

    Plugins should mix this in to continuations for which it is useful.
    The default implementations return empty / invalid responses and should
    be overridden by the plugin.
 */
class PluginIdentity
{
public:
  /// Make sure destructor is virtual.
  virtual ~PluginIdentity() {}
  /** Get the plugin tag.
      The returned string must have a lifetime at least as long as the plugin.
      @return A string identifying the plugin or @c NULL.
  */
  virtual char const *
  getPluginTag() const
  {
    return nullptr;
  }
  /** Get the plugin instance ID.
      A plugin can create multiple subsidiary instances. This is used as the
      identifier for those to distinguish the instances.
  */
  virtual int64_t
  getPluginId() const
  {
    return 0;
  }
};
