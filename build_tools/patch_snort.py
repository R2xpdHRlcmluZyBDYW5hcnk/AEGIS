# SPDX-License-Identifier: GPL-2.0-only
# Snort 3.12.4.0 matching fragments: https://github.com/snort3/snort3/tree/3.12.4.0
# NDR session changes maintained by this project, 2026-11-04.
# Upstream terms and notices: ../LICENSES/Snort-COPYING.txt.
"""Add an engine-owned, process-scoped connection identity to the pinned Snort."""
from pathlib import Path

REVISION = 'ndr-session-1'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Snort session patch does not match the pinned source: '+old[:80])
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
    edit('stream/udp/udp_session.cc','        flow->restart();','        flow->restart();\n        flow->begin_ndr_session();')
    edit('network_inspectors/extractor/extractors.cc','    {"uid", ExtractorEvent::get_uid},','    {"uid", ExtractorEvent::get_uid},\n    {"session_id", [](const DataEvent*, const Flow* flow) -> uint64_t { return flow->ndr_session_id; }},')
    edit('network_inspectors/extractor/extractor_service.cc','    "uid",','    "uid",\n    "session_id",')
    edit('network_inspectors/extractor/extractors.h','    template<typename T, class... Context>\n    void log(', '''    void log(const std::vector<NumField>& fields, DataEvent* event, Flow* flow)
    {
        for (const auto& field : fields)
            if (std::string(field.name) == "session_id")
                logger->add_field(field.name, flow->ndr_session_id ? flow->ndr_session_label() : "");
            else
                logger->add_field(field.name, field.get(event, flow));
    }

    template<typename T, class... Context>
    void log(''')
    (root.parent/'ndr-session-patch.txt').write_text(REVISION+'\n')


if __name__=='__main__':
    import sys
    patch(sys.argv[1])
