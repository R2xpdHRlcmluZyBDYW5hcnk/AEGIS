# SPDX-License-Identifier: GPL-2.0-only
# Snort 3.13.2.0 matching fragments: https://github.com/snort3/snort3/tree/3.13.2.0
# NDR session changes maintained by this project, 2026-11-04.
# Upstream terms and notices: ../LICENSES/Snort-COPYING.txt.
"""Add connection identities and suppressed block records to the pinned Snort."""
from pathlib import Path

REVISION = 'ndr-session-3'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Snort patch does not match the pinned source: '+old[:80])
    return text.replace(old,new,1)


def patch(root):
    root=Path(root)/'src'
    def edit(name, old, new):
        path=root/name
        path.write_text(replace_once(path.read_text(),old,new))
    edit('flow/flow.h','    void init(PktType);', '''    void init(PktType);
    void begin_ndr_session();
    void end_ndr_session();
    const char* ndr_session_label() const;
    uint64_t ndr_session_id = 0;
    bool ndr_session_open = false;''')
    edit('flow/flow.cc','#include "flow.h"', '#include "flow.h"\n#include <cerrno>\n#include <cstdio>\n#include <sys/random.h>\n#include "log/messages.h"')
    edit('flow/flow.cc','extern THREAD_LOCAL class FlowControl* flow_con;', '''extern THREAD_LOCAL class FlowControl* flow_con;

namespace
{
const std::string& ndr_instance()
{
    static const std::string value = []()
    {
        unsigned char random[16];
        size_t offset = 0;
        while (offset < sizeof(random))
        {
            ssize_t n = getrandom(random + offset, sizeof(random) - offset, 0);
            if (n < 0 and errno == EINTR)
                continue;
            if (n <= 0)
                FatalError("Cannot initialize NDR session identity\\n");
            offset += n;
        }
        char hex[33];
        for (size_t i = 0; i < sizeof(random); ++i)
            snprintf(hex + 2*i, 3, "%02x", random[i]);
        return std::string(hex);
    }();
    return value;
}
std::atomic<uint64_t> ndr_sequence{0};
}

void Flow::begin_ndr_session()
{
    if (ndr_session_open)
        return;
    (void)ndr_instance();
    ndr_session_id = ndr_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    if (!ndr_session_id)
        FatalError("NDR session sequence exhausted\\n");
    ndr_session_open = true;
}

const char* Flow::ndr_session_label() const
{
    static thread_local char value[50];
    snprintf(value, sizeof(value), "%s:%016llx", ndr_instance().c_str(),
        static_cast<unsigned long long>(ndr_session_id));
    return value;
}

void Flow::end_ndr_session()
{
    if (!ndr_session_open)
        return;
    EofEvent event(this);
    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_END, event, this);
    ndr_session_open = false;
}''')
    edit('flow/flow.cc','    EofEvent eof_event(this);\n    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_END, eof_event, this);','    end_ndr_session();')
    edit('flow/flow.cc','void Flow::init(PktType type)\n{','void Flow::init(PktType type)\n{\n    begin_ndr_session();')
    edit('flow/flow.cc','void Flow::restart(bool dump_flow_data)\n{\n    DetectionEngine::onload(this);','void Flow::restart(bool dump_flow_data)\n{\n    DetectionEngine::onload(this);\n    end_ndr_session();')
    edit('flow/flow_control.cc','    p->flow = flow;\n    p->disable_inspect = flow->is_inspection_disabled();','    p->flow = flow;\n    flow->begin_ndr_session();\n    p->disable_inspect = flow->is_inspection_disabled();')
    edit('stream/tcp/tcp_session.cc','void TcpSession::init_new_tcp_session(const TcpSegmentDescriptor& tsd)\n{','void TcpSession::init_new_tcp_session(const TcpSegmentDescriptor& tsd)\n{\n    flow->begin_ndr_session();')
    edit('flow/flow.cc','    // A packet-triggered restart begins a new logical session',
         '    begin_ndr_session();\n\n    // A packet-triggered restart begins a new logical session')
    edit('network_inspectors/extractor/extractors.cc','    {"uid", ExtractorEvent::get_uid},','    {"uid", ExtractorEvent::get_uid},\n    {"session_id", [](const DataEvent*, const Flow* flow) -> uint64_t { return flow->ndr_session_id; }},')
    edit('network_inspectors/extractor/extractor_service.cc','    "uid",','    "uid",\n    "session_id",')
    edit('network_inspectors/extractor/extractors.h','    template<typename T, class... Context>\n    static void log(', '''    static void log(const std::vector<NumField>& fields, DataEvent* event, Flow* flow)
    {
        for (const auto& field : fields)
            if (std::string(field.name) == "session_id")
                logger->add_field(field.name, flow->ndr_session_id ? flow->ndr_session_label() : "");
            else
                logger->add_field(field.name, field.get(event, flow));
    }

    template<typename T, class... Context>
    static void log(''')
    patch_suppressed_blocks(edit)
    patch_log_rotation(edit)
    (root.parent/'ndr-session-patch.txt').write_text(REVISION+'\n')


def patch_suppressed_blocks(edit):
    edit('detection/ips_context.h', 'struct OtnxMatchData;', 'struct OtnxMatchData;\nstruct OptTreeNode;')
    edit('detection/ips_context.h', '    std::vector<MatchedBuffer> matched_buffers;', '''    std::vector<MatchedBuffer> matched_buffers;

    const OptTreeNode* suppressed_block_rule = nullptr;
    const char* suppressed_block_action = nullptr;''')
    edit('main/analyzer.cc', '    p->context->wire_packet = p;', '''    p->context->wire_packet = p;
    p->context->suppressed_block_rule = nullptr;''')
    edit('detection/fp_detect.cc', '        ActInfo ai(otn, false);\n        act->exec(p, ai);', '''        const bool already_dropping = p->active && p->active->packet_was_dropped();
        ActInfo ai(otn, false);
        act->exec(p, ai);

        // Reassembled packets share the wire packet's eventual DAQ verdict.
        auto* wire = p->context->wire_packet;
        if (event_filter < 0 && wire && p->flow && p->active && !already_dropping &&
            p->active->packet_was_dropped() && p->active->can_act() &&
            !wire->context->suppressed_block_rule)
        {
            wire->context->suppressed_block_rule = otn;
            wire->context->suppressed_block_action = act->get_name();
        }''')
    edit('detection/detect.h', 'void CallAlertFuncs(snort::Packet*, const OptTreeNode*, ListHead*);', '''void CallAlertFuncs(snort::Packet*, const OptTreeNode*, ListHead*);
void publish_suppressed_block(snort::Packet*, const OptTreeNode*, const char* action);''')
    edit('detection/detect.cc', 'void CallLogFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)', '''void publish_suppressed_block(Packet* p, const OptTreeNode* otn, const char* action)
{
    Event event(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec, otn->sigInfo, otn->buffer_setters, action);
    IpsRuleEvent record(event, true);
    DataBus::publish(DetectionEngine::get_pub_id(), DetectionEventIds::SUPPRESSED_BLOCK, record, p->flow);
}

void CallLogFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)''')
    edit('main/analyzer.cc', '            p->active->send_reason_to_daq(*p);', '''        {
            p->active->send_reason_to_daq(*p);
            if (p->flow && p->context->suppressed_block_rule)
                publish_suppressed_block(p, p->context->suppressed_block_rule,
                    p->context->suppressed_block_action);
        }''')
    edit('pub_sub/detection_events.h', '        MAX\n', '        SUPPRESSED_BLOCK, // a suppressed rule caused an inline block verdict\n        MAX\n')
    edit('pub_sub/detection_events.h', '    IpsRuleEvent(const Event& e) : Event(e) {}', '''    IpsRuleEvent(const Event& e, bool suppressed = false) : Event(e), alert_suppressed(suppressed) {}
    const bool alert_suppressed;''')
    edit('network_inspectors/extractor/extractor.cc', '        INSAPI_VERSION,\n        0,', '        INSAPI_VERSION,\n        1,')
    edit('network_inspectors/extractor/extractor_service.cc', '        "ips_action",', '        "ips_action",\n        "alert_suppressed",')
    edit('network_inspectors/extractor/extractor_detection.cc', '    {"rev", get_rev},', '''    {"rev", get_rev},
    {"alert_suppressed", [](const DataEvent* event, const Flow*) -> uint64_t
        { return static_cast<const IpsRuleEvent*>(event)->alert_suppressed; }},''')
    edit('network_inspectors/extractor/extractor_detection.cc', '    DataBus::subscribe_global(de_pub_key, event, new IpsUser(*this, S_NAME), i.get_snort_config());', '''    DataBus::subscribe_global(de_pub_key, event, new IpsUser(*this, S_NAME), i.get_snort_config());
    if (!contextual && find(fields.begin(), fields.end(), "alert_suppressed") != fields.end())
        DataBus::subscribe_global(de_pub_key, DetectionEventIds::SUPPRESSED_BLOCK,
            new IpsUser(*this, S_NAME), i.get_snort_config());''')


def patch_log_rotation(edit):
    # Reopen output handles on their owning packet thread. No DAQ, flow, rule,
    # inspector or session lifecycle is stopped or reset by this command.
    edit('log/text_log.cc', '#include <cstdarg>', '#include <cstdarg>\n#include <vector>')
    edit('log/text_log.cc', 'namespace snort\n{', 'static thread_local std::vector<TextLog*> active_text_logs;\n\nnamespace snort\n{')
    edit('log/text_log.cc', '    TextLog_Reset(txt);\n\n    return txt;', '    TextLog_Reset(txt);\n    active_text_logs.push_back(txt);\n\n    return txt;')
    edit('log/text_log.cc', '    snort_free(txt->name);', '    active_text_logs.erase(std::remove(active_text_logs.begin(), active_text_logs.end(), txt), active_text_logs.end());\n    snort_free(txt->name);')
    edit('log/text_log.h', 'SO_PUBLIC void TextLog_Term(TextLog*);', 'SO_PUBLIC void TextLog_Term(TextLog*);\nSO_PUBLIC bool TextLog_ReopenAll();')
    edit('log/text_log.cc', 'void TextLog_Term(TextLog* const txt)', '''bool TextLog_ReopenAll()
{
    std::vector<std::pair<TextLog*, FILE*>> replacements;
    bool ready = true;
    for (auto* log : active_text_logs)
    {
        if (log->file == stdout) continue;
        FILE* next = TextLog_Open(log->name, false);
        if (!next) { ready = false; break; }
        replacements.emplace_back(log, next);
        size_t limit = log->maxFile;
        log->maxFile = 0;
        bool flushed = !log->pos || TextLog_Flush(log);
        log->maxFile = limit;
        if (!flushed || fflush(log->file))
        { ready = false; break; }
    }
    if (!ready)
    {
        for (auto& entry : replacements) fclose(entry.second);
        return false;
    }
    for (auto& entry : replacements)
    {
        auto* log = entry.first;
        TextLog_Close(log->file);
        log->file = entry.second;
        log->size = TextLog_Size(log->file);
        log->last = time(nullptr);
    }
    return true;
}

void TextLog_Term(TextLog* const txt)''')
    edit('connectors/file_connector/file_connector.h', '    { file.flush(); return file.good(); }', '''    { file.flush(); return file.good() && !rotation_failed; }

    void reinit() override;
    std::string output_path;
    bool rotation_failed = false;''')
    edit('connectors/file_connector/file_connector.cc', '    file_conn->file.open(pathname,\n', '    file_conn->output_path = pathname;\n    file_conn->file.open(pathname,\n')
    edit('connectors/file_connector/file_connector.cc', '(std::ios::out | (cfg.text_format', '(std::ios::out | std::ios::app | (cfg.text_format')
    edit('connectors/file_connector/file_connector.cc', 'bool FileConnector::internal_transmit_message', '''void FileConnector::reinit()
{
    if (output_path.empty()) return;
    file.flush();
    std::fstream next;
    next.open(output_path, std::ios::out | std::ios::app |
        (cfg.text_format ? (std::ios::openmode)0 : std::ios::binary));
    rotation_failed = !next.good() || !file.good();
    if (!rotation_failed) file.swap(next);
}

bool FileConnector::internal_transmit_message''')
    edit('managers/connector_manager.h', '    static void thread_reinit();', '    static void thread_reinit();\n    static bool reopen_log_files();')
    edit('managers/connector_manager.cc', 'void ConnectorManager::thread_reinit()', '''bool ConnectorManager::reopen_log_files()
{
    bool ready = true;
    unsigned instance = get_instance_id();
    for (auto* entry : PluginManager::get_interfaces(PT_CONNECTOR))
    {
        auto* group = static_cast<ConnectorCommonElem*>(entry);
        if (std::string(group->api->base.name) != "file_connector") continue;
        for (auto& item : group->connectors)
        {
            auto* connector = item.second.thread_connectors[instance];
            if (!connector || connector->get_connector_direction() != Connector::CONN_TRANSMIT) continue;
            connector->reinit();
            if (!connector->flush()) ready = false;
        }
    }
    return ready;
}

void ConnectorManager::thread_reinit()''')
    edit('main/analyzer_command.h', 'class ACRotate :', '''class ACReopenLogs : public snort::AnalyzerCommand
{
public:
    explicit ACReopenLogs(ControlConn* conn) : AnalyzerCommand(conn) { }
    ~ACReopenLogs() override;
    bool execute(Analyzer&) override;
    const char* stringify() override { return "REOPEN_LOGS"; }
private:
    std::atomic<unsigned> failures{0};
    std::atomic<unsigned> completed{0};
};

class ACRotate :''')
    edit('main/analyzer_command.h', '#define ANALYZER_COMMANDS_H', '#define ANALYZER_COMMANDS_H\n#include <atomic>')
    edit('main/analyzer_command.cc', '#include "control/control.h"', '#include "control/control.h"\n#include "log/text_log.h"\n#include "managers/connector_manager.h"')
    edit('main/analyzer_command.cc', 'bool ACRotate::execute', '''bool ACReopenLogs::execute(Analyzer&)
{
    bool text_ready = TextLog_ReopenAll();
    bool connector_ready = ConnectorManager::reopen_log_files();
    if (!text_ready || !connector_ready) ++failures;
    ++completed;
    return true;
}

ACReopenLogs::~ACReopenLogs()
{
    if (failures || !completed)
        log_message("NDR_LOGS_REOPEN_FAILED threads=%u failures=%u\\n", completed.load(), failures.load());
    else
        log_message("NDR_LOGS_REOPENED threads=%u\\n", completed.load());
}

bool ACRotate::execute''')
    edit('main.h', 'int main_rotate_stats(lua_State* = nullptr);', 'int main_rotate_stats(lua_State* = nullptr);\nint main_reopen_logs(lua_State* = nullptr);')
    edit('main.cc', 'int main_rotate_stats(lua_State* L)', '''int main_reopen_logs(lua_State* L)
{
    ControlConn* connection = ControlConn::query_from_lua(L);
    main_broadcast_command(new ACReopenLogs(connection), connection);
    return 0;
}

int main_rotate_stats(lua_State* L)''')
    edit('main/snort_module.cc', '    { "rotate_stats", main_rotate_stats, nullptr, "roll perfmonitor log files" },', '    { "rotate_stats", main_rotate_stats, nullptr, "roll perfmonitor log files" },\n    { "reopen_logs", main_reopen_logs, nullptr, "reopen event log files on every packet thread" },')


if __name__=='__main__':
    import sys
    patch(sys.argv[1])
