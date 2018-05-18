#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <arpa/inet.h>

#include <sstream>
#include <iomanip>
#include <chrono>
#include <atomic>
#include <string>

#include "ts/ts.h"

const char* PLUGIN_NAME = "traffic_dump";
static const std::string closing = "]}]}";

static std::string LOG_DIR = "dump";             // default  log directory
static int s_arg_idx = 0;                 // Session Arg Index to pass on session data
static std::atomic<int64_t> sample_pool_size(1000);

// handler declaration
static int session_aio_handler(TSCont contp, TSEvent event, void* edata);
static int session_txn_handler(TSCont contp, TSEvent event, void* edata);

struct SsnData {
  int           log_fd        = -1;       // Log file descriptor
  TSCont        aio_cont      = nullptr;  // AIO callback
  TSCont        txn_cont      = nullptr;  // Transaction callback
  bool          ssn_closed    = false;    // Session closed flag
  int           aio_count     = 0;        // Active AIO counts
  int64_t       write_offset  = 0;        // AIO write offset
  TSMutex       disk_io_mutex = nullptr;  // AIO mutex
  bool          first         = true;     // First Transaction

  SsnData() {
    disk_io_mutex = TSMutexCreate();
    aio_cont = TSContCreate(session_aio_handler, TSMutexCreate());
    txn_cont = TSContCreate(session_txn_handler, nullptr);
  }

  ~SsnData() {
    if (disk_io_mutex) {
      TSMutexDestroy(disk_io_mutex);
    }
    if (aio_cont) {
      TSContDestroy(aio_cont);
    }
    if (txn_cont) {
      TSContDestroy(txn_cont);
    }
  }

  /// write_to_disk(): Takes a string object and writes to file via AIO
  int
  write_to_disk(const std::string& body)
  {
    TSMutexLock(disk_io_mutex);
    char* pBuf = nullptr;
    if ((pBuf = static_cast<char*>(TSmalloc(sizeof(char)*body.size())))) {
      memcpy(pBuf, body.c_str(), body.size());
      if (TS_SUCCESS == TSAIOWrite(log_fd, write_offset, pBuf, body.size(), aio_cont)) {
        // Update offset within file and aio events count
        write_offset += body.size();
        aio_count += 1;

        TSMutexUnlock(disk_io_mutex);
        return TS_SUCCESS;
      }
      TSfree(pBuf);
    }
    TSMutexUnlock(disk_io_mutex);
    return TS_ERROR;
  }
};

/// Local helper functions about json formatting
/// min_write(): Inline function for repeating code
static inline void
min_write(const char* buf, int64_t &prevIdx, int64_t &idx, std::ostream &jsonfile)
{
  if(prevIdx < idx) {
    jsonfile.write(buf+prevIdx, idx-prevIdx);
  }
  prevIdx = idx+1;
}
/// esc_json_out(): Escape characters in a buffer and output to ofstream object
///                 in a way to minimize ofstream operations
static int
esc_json_out(const char* buf, int64_t len, std::ostream &jsonfile)
{
  if (buf == nullptr) return 0;
  int64_t idx, prevIdx = 0;
  for (idx = 0; idx < len; idx++) {
    char c = *(buf+idx);
    switch(c) {
      case '"':
      case '\\': {
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\" << c;
        break;
      }
      case '\b': {
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\b";
        break;
      }
      case '\f':{
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\f";
        break;
      }
      case '\n':{
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\n";
        break;
      }
      case '\r':{
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\r";
        break;
      }
      case '\t': {
        min_write(buf, prevIdx, idx, jsonfile);
        jsonfile << "\\t";
        break;
      }
      default: {
        if ('\x00' <= c && c <= '\x1f') {
          min_write(buf, prevIdx, idx, jsonfile);
          jsonfile << "\\u"
            << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        }
        break;
      }
    }
  }
  min_write(buf, prevIdx, idx, jsonfile);

  return len;
}

/// escape_json(): escape chars in a string and returns json string
static std::string
escape_json(std::string const &s)
{
    std::ostringstream o;
    esc_json_out(s.c_str(), s.length(), o);
    return o.str();
}
static std::string
escape_json(const char* buf, int64_t size)
{
  std::ostringstream o;
  esc_json_out(buf, size, o);
  return o.str();
}

/// json_entry(): Formats to map-style entry i.e. "field": "value"
static inline std::string
json_entry(std::string const &name, std::string const &value)
{
  return "\"" + escape_json(name) + "\": \"" + escape_json(value) + "\"";
}

static inline std::string
json_entry(std::string const &name, const char* buf, int64_t size)
{
  return "\"" + escape_json(name) + "\":\"" + escape_json(buf,size) + "\"";
}

/// json_entry_array(): Formats to array-style entry i.e. ["field","value"]
static inline std::string
json_entry_array(std::string const &name, std::string const &value)
{
  return "[\"" + escape_json(name) + "\", \"" + escape_json(value) + "\"]";
}

static inline std::string
json_entry_array(const char* name, int name_len, const char* value, int value_len)
{
  return "[\"" + escape_json(name,name_len) + "\", \"" + escape_json(value,value_len) + "\"]";
}

/// Helper functions to collect txn information from TSMBuffer
static std::string
collect_headers(TSMBuffer &buffer, TSMLoc &hdr_loc, int64_t body_bytes)
{
  std::string result = "{";
  int len = 0;
  const char *cp = nullptr;
  TSMLoc url_loc = nullptr;


  // Log scheme+method or status+reason based on header type
  if (TSHttpHdrTypeGet(buffer, hdr_loc) == TS_HTTP_TYPE_REQUEST) {
    // 1. "scheme":(string)
    TSAssert(TS_SUCCESS == TSHttpHdrUrlGet(buffer, hdr_loc, &url_loc));
    cp = TSUrlSchemeGet(buffer, url_loc, &len);
    TSDebug(PLUGIN_NAME, "collect_headers(): found scheme %d ", len);
    result += json_entry("scheme", cp, len);
    cp = TSUrlStringGet(buffer, url_loc, &len);
    TSDebug(PLUGIN_NAME, "collect_headers(): found url %.*s", len, cp);
    TSHandleMLocRelease(buffer, hdr_loc, url_loc);

    // 2. "method":(string)
    cp = TSHttpHdrMethodGet(buffer, hdr_loc, &len);
    result += ","+json_entry("method", cp, len);
  } else {
    // 1. "status":(string)
    result += json_entry("status",std::to_string(TSHttpHdrStatusGet(buffer, hdr_loc)));
    // 2. "reason":(string)
    cp = TSHttpHdrReasonGet(buffer, hdr_loc, &len);
    result += ","+json_entry("reason", cp, len);
  }

  // "encoding":"esc_json"
  result += ",\"encoding\":\"esc_json\"";

  // "content-size":(integer)
  result += ",\"content-size\":"+std::to_string(body_bytes);

  // "fields": [[name(string), value(string)]]
  result += ",\"fields\":[";
  TSMLoc field_loc = TSMimeHdrFieldGet(buffer, hdr_loc, 0);
  while (field_loc) {
    TSMLoc next_field_loc;
    const char *name;
    const char *value;
    int name_len, value_len;
    // Append to "fields" list if valid value exists
    if ((name = TSMimeHdrFieldNameGet(buffer, hdr_loc, field_loc, &name_len)) && name_len) {
      value = TSMimeHdrFieldValueStringGet(buffer, hdr_loc, field_loc, -1, &value_len);
      result += json_entry_array(name, name_len, value, value_len);
    }

    next_field_loc = TSMimeHdrFieldNext(buffer, hdr_loc, field_loc);
    TSHandleMLocRelease(buffer, hdr_loc, field_loc);
    if ((field_loc = next_field_loc) != nullptr) {
      result += ",";
    }
  }

  return result+"]}";
}

// Per session AIO handler: update AIO counts and clean up
int
session_aio_handler(TSCont contp, TSEvent event, void* edata)
{
  switch (event) {
    case TS_AIO_EVENT_DONE: {
      TSAIOCallback cb = static_cast<TSAIOCallback>(edata);
      SsnData *ssnData = static_cast<SsnData*>(TSContDataGet(contp));
      if (!ssnData) {
        TSDebug(PLUGIN_NAME, "session_aio_handler(): No valid ssnData. Abort.");
        return TS_ERROR;
      }
      char *buf = TSAIOBufGet(cb);
      TSMutexLock(ssnData->disk_io_mutex);
      if (buf) {
        TSfree(buf);
        if (--ssnData->aio_count == 0 && ssnData->ssn_closed) {
          // check for ssn close, if closed, do clean up
          TSContDataSet(contp, nullptr);
          close(ssnData->log_fd);
          TSMutexUnlock(ssnData->disk_io_mutex);
          delete ssnData;
          return TS_SUCCESS;
        }
      }
      TSMutexUnlock(ssnData->disk_io_mutex);
      return TS_SUCCESS;
    }
    default:
      TSDebug(PLUGIN_NAME, "session_aio_handler(): unhandled events %d", event);
      return TS_ERROR;
  }
  return TS_SUCCESS;
}

// Transaction handler: writes headers to the log file using AIO
int
session_txn_handler(TSCont contp, TSEvent event, void* edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  // Retrieve SsnData
  TSHttpSsn ssnp = TSHttpTxnSsnGet(txnp);
  SsnData* ssnData = static_cast<SsnData*>(TSHttpSsnArgGet(ssnp, s_arg_idx));

  // If no valid ssnData, continue transaction as if nothing happened
  if (!ssnData) {
    TSDebug(PLUGIN_NAME, "session_txn_handler(): No ssnData found. Abort.");
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return TS_SUCCESS;
  }

  switch (event) {
    case TS_EVENT_HTTP_TXN_CLOSE: {
      // Get UUID
      char uuid[TS_CRUUID_STRING_LEN+1];
      TSAssert(TS_SUCCESS == TSClientRequestUuidGet(txnp, uuid));

      // Generate per transaction json records
      std::string txn_info;
      if (!ssnData->first) {
        txn_info += ",";
      }
      ssnData->first = false;

      // "uuid":(string)
      txn_info += "{"+ json_entry("uuid", uuid, strlen(uuid));

      // "connect-time":(number)
      TSHRTime start_time;
      TSHttpTxnMilestoneGet(txnp, TS_MILESTONE_UA_BEGIN, &start_time);
      txn_info += ",\"start-time\":" + std::to_string(start_time);

      // client/proxy-request/response headers
      TSMBuffer buffer;
      TSMLoc hdr_loc;
      if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buffer, &hdr_loc)) {
        txn_info += ",\"client-request\":" + collect_headers(buffer, hdr_loc, TSHttpTxnClientReqBodyBytesGet(txnp));
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr_loc);
        buffer = nullptr;
      }
      if (TS_SUCCESS == TSHttpTxnServerReqGet(txnp, &buffer, &hdr_loc)) {
        txn_info += ",\"server-request\":" + collect_headers(buffer, hdr_loc, TSHttpTxnServerReqBodyBytesGet(txnp));
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr_loc);
        buffer = nullptr;
      }
      if (TS_SUCCESS == TSHttpTxnClientRespGet(txnp, &buffer, &hdr_loc)) {
        txn_info += ",\"client-response\":" + collect_headers(buffer, hdr_loc, TSHttpTxnServerRespBodyBytesGet(txnp));
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr_loc);
        buffer = nullptr;
      }
      if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &buffer, &hdr_loc)) {
        txn_info += ",\"server-response\":" + collect_headers(buffer, hdr_loc, TSHttpTxnClientRespBodyBytesGet(txnp));
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr_loc);
        buffer = nullptr;
      }
      txn_info += "}";
      ssnData->write_to_disk(txn_info);
      break;
    }
    default:
      TSDebug(PLUGIN_NAME, "session_txn_handler(): Unhandled events %d", event);
      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
      return TS_ERROR;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return TS_SUCCESS;
}

// Session handler for global hooks; Assign per-session data structure and log files
static int
global_ssn_handler(TSCont contp, TSEvent event, void* edata)
{
  TSHttpSsn ssnp = static_cast<TSHttpSsn>(edata);

  switch (event) {
    case TS_EVENT_LIFECYCLE_MSG: {
      TSPluginMsg *msg = static_cast<TSPluginMsg*>(edata);
      if (strlen(msg->tag) == 19 && strncmp(msg->tag,"traffic_dump.sample",19) == 0) {
        sample_pool_size = static_cast<int64_t>(strtol(static_cast<const char*>(msg->data), nullptr, 0));
        TSDebug(PLUGIN_NAME, "global_ssn_handler(): Received Msg to change sample size to %" PRId64 "", sample_pool_size.load());
      }
      return TS_SUCCESS;
    }
    case TS_EVENT_HTTP_SSN_START: {
      // Grab session id to do sampling
      int64_t id = TSHttpSsnIdGet(ssnp);
      if (id % sample_pool_size != 0) {
        TSDebug(PLUGIN_NAME, "global_ssn_handler(): Ignore session %" PRId64 "...", id);
        break;
      }
      // Beginning of a new session
      /// Get epoch time
      auto start = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch());

      // Create new per session data
      SsnData* ssnData = new SsnData;
      TSHttpSsnArgSet(ssnp, s_arg_idx, ssnData);

      TSContDataSet(ssnData->aio_cont, ssnData);

      // Generate file openning string


      // 1. "protocol":(string)
      const char *protocol[10];
      int count = 0;
      TSAssert(TS_SUCCESS == TSHttpSsnClientProtocolStackGet(ssnp, 10, protocol, &count));
      std::string result;
      for (int i = 0; i < count; i++) {
        if (i > 0) {
          result += ",";
        }
        result += protocol[i];
      }
      std::string beginning = "{\"meta\":{\"version\":\"1.0\"},\"sessions\":[{" + json_entry("protocol", result)
                              + ",\"connection-time\":" + std::to_string(start.count())+",\"transactions\":[";

      // Grab session id and use its hex string as fname
      std::stringstream stream;
      stream << std::setw(16) << std::setfill('0') << std::hex << id;
      std::string session_id = stream.str();

      // Use client ip as sub directory name
      char client_str[INET6_ADDRSTRLEN];
      const sockaddr *client_ip = TSHttpSsnClientAddrGet(ssnp);
      if (AF_INET == client_ip->sa_family) {
        inet_ntop(AF_INET, &(reinterpret_cast<const sockaddr_in *>(client_ip)->sin_addr), client_str, INET_ADDRSTRLEN);
      } else if (AF_INET6 == client_ip->sa_family) {
        inet_ntop(AF_INET6, &(reinterpret_cast<const sockaddr_in6 *>(client_ip)->sin6_addr), client_str, INET6_ADDRSTRLEN);
      } else {
        TSDebug(PLUGIN_NAME, "global_ssn_handler(): Unknown address family.");
        strncpy(client_str, "unknown", 7);
      }

      // Initialize AIO file
      TSMutexLock(ssnData->disk_io_mutex);
      if (ssnData->log_fd < 0) {
        std::string path = LOG_DIR + "/" + client_str;
        std::string fname = path + "/" + session_id;

        // Create subdir if not existing
        struct stat st;
        if (stat(path.c_str(),&st) == -1) {
          if (mkdir(path.c_str(), 0755) == -1) {
            TSDebug(PLUGIN_NAME, "global_ssn_handler(): failed to create dir");
            TSError("[%s] Failed to create dir.", PLUGIN_NAME);
          }
        }

        // Try to open log files for AIO
        ssnData->log_fd = open(fname.c_str(), O_RDWR | O_CREAT, S_IRWXU);
        if (ssnData->log_fd < 0) {
          TSMutexUnlock(ssnData->disk_io_mutex);
          TSDebug(PLUGIN_NAME, "global_ssn_handler(): Failed to open log files. Abort.");
          TSHttpSsnReenable(ssnp, TS_EVENT_HTTP_CONTINUE);
          return TS_EVENT_HTTP_CONTINUE;
        }

        // Write log file beginning to disk
        ssnData->write_to_disk(beginning);
      }
      TSMutexUnlock(ssnData->disk_io_mutex);

      TSHttpSsnHookAdd(ssnp, TS_HTTP_TXN_CLOSE_HOOK, ssnData->txn_cont);
      break;
    }
    case TS_EVENT_HTTP_SSN_CLOSE: {
      // Write session and log file closing
      int64_t id = TSHttpSsnIdGet(ssnp);
      TSDebug(PLUGIN_NAME, "global_ssn_handler(): Closing session %" PRId64 "...", id);
      // Retrieve SsnData
      SsnData* ssnData = static_cast<SsnData*>(TSHttpSsnArgGet(ssnp, s_arg_idx));
      // If no valid ssnData, continue transaction as if nothing happened
      if (!ssnData) {
        TSDebug(PLUGIN_NAME, "global_ssn_handler(): [TS_EVENT_HTTP_SSN_CLOSE] No ssnData found. Abort.");
        TSHttpSsnReenable(ssnp, TS_EVENT_HTTP_CONTINUE);
        return TS_SUCCESS;
      }
      ssnData->write_to_disk(closing);
      TSMutexLock(ssnData->disk_io_mutex);
      ssnData->ssn_closed = true;
      TSMutexUnlock(ssnData->disk_io_mutex);

      break;
    }
    default:
      break;
  }
  TSHttpSsnReenable(ssnp, TS_EVENT_HTTP_CONTINUE);
  return TS_SUCCESS;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSDebug(PLUGIN_NAME, "initializing plugin");
  TSPluginRegistrationInfo info;

  info.plugin_name = "traffic_dump";
  info.vendor_name   = "Oath";
  info.support_email = "edge@oath.com";

  std::string installDir = TSInstallDirGet();
  LOG_DIR = installDir + "/" + LOG_DIR + "/";

  /// Commandline options
  static const struct option longopts[] = {
    {"logdir",  required_argument, nullptr,  'l'},
    {"sample",  required_argument, nullptr,  's'},
    {nullptr,   no_argument,       nullptr,  0 }
  };
  int opt = 0;
  while (opt >= 0) {
    opt = getopt_long(argc, (char *const *)argv, "l:", longopts, nullptr);
    switch (opt) {
      case 'l': {
        LOG_DIR = std::string(optarg);
        if (LOG_DIR[0] != '/') {
          LOG_DIR = installDir + "/" + std::string(optarg) + "/";
        }
        break;
      }
      case 's': {
        sample_pool_size = static_cast<int64_t>(std::strtol(optarg, nullptr, 0));
        break;
      }
      case -1:
      case '?':
        break;

      default:
        TSDebug(PLUGIN_NAME, "Unexpected options.");
        TSError("[%s] Unexpected options error.", PLUGIN_NAME);
        return;
    }
  }

  if(TS_SUCCESS != TSPluginRegister(&info)) {
   TSError("[%s] Unable to initialize plugin (disabled). Failed to register plugin.", PLUGIN_NAME);
  } else if (TS_SUCCESS != TSHttpArgIndexReserve(PLUGIN_NAME, "Track log related data", &s_arg_idx)) {
    TSError("[%s] Unable to initialize plugin (disabled). Failed to reserve ssn arg.", PLUGIN_NAME);
  } else {
    /// Add global hooks
    TSCont ssncont = TSContCreate(global_ssn_handler, nullptr);
    TSHttpHookAdd(TS_HTTP_SSN_START_HOOK, ssncont);
    TSHttpHookAdd(TS_HTTP_SSN_CLOSE_HOOK, ssncont);
    TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, ssncont);
    TSDebug(PLUGIN_NAME, "Initialized with sample pool size %" PRId64 "", sample_pool_size.load());
  }

  return;
}
