// SPDX-License-Identifier: GPL-2.0-only
// Snort 3.12.4.0 extension using its published Flow, AppID and DataBus APIs.
// Build against matching session-patched headers; see build_tools/patch_snort.py.
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "network_inspectors/appid/appid_api.h"
#include "protocols/packet.h"
#include "protocols/icmp4.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "stream/tcp/tcp_session.h"

using namespace snort;
namespace {
constexpr const char* NAME="ndr_session";
unsigned flow_slot=0;
bool supported(Flow* flow)
{
    return flow && (flow->pkt_type==PktType::TCP || flow->pkt_type==PktType::UDP || flow->pkt_type==PktType::ICMP || flow->pkt_type==PktType::IP);
}
struct Settings { unsigned interval=30; unsigned state_limit=32; };

// JSON escaping is independent of Lua, shell and format string syntax.
std::string quoted(const char* value)
{
    std::ostringstream out;out<<'"';
    if (value) for (unsigned i=0;i<253 && value[i];++i)
    {
        unsigned char c=value[i];
        if (c=='"' || c=='\\') out<<'\\'<<char(c);
        else if (c<32) out<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(c)<<std::dec;
        else if (c<128) out<<char(c);
        else
        {
            unsigned length=c>=0xc2 && c<=0xdf?2:c>=0xe0 && c<=0xef?3:c>=0xf0 && c<=0xf4?4:0;
            bool valid=length && i+length<=253;
            for (unsigned j=1;valid && j<length;++j)
            {
                unsigned char next=value[i+j];
                valid=next>=0x80 && next<=0xbf;
                if (j==1 && ((c==0xe0 && next<0xa0) || (c==0xed && next>=0xa0) ||
                            (c==0xf0 && next<0x90) || (c==0xf4 && next>=0x90))) valid=false;
            }
            if (valid) { out.write(value+i,length);i+=length-1; }
            else out<<"\\ufffd";
        }
    }
    out<<'"';return out.str();
}

struct Evidence : FlowData
{
    Evidence(uint64_t id) : FlowData(flow_slot,NAME), identity(id) { }
    uint64_t identity;
    double first=0,last=0,published=0;
    unsigned state_events=0,app_events=0;
    int client=-1,server=-1;
    bool initial_syn=false,limited=false;
    std::array<AppId,5> applications{};
    bool packet_seen=false,tcp_seen=false,icmp_seen=false;
    double packet_time=0;
    unsigned packet_length=0,data_length=0,ttl=0,tos=0,ip_id=0,ip_offset=0,ip_flags=0,ip_proto=0,ip_header_len=0;
    unsigned tcp_flags=0,tcp_window=0,tcp_options=0;
    uint32_t tcp_seq=0,tcp_ack=0;
    unsigned icmp_type=0,icmp_code=0;
    const char* direction="unknown";
};

class SessionInspector;
class Handler : public DataHandler
{
public:
    Handler(SessionInspector& inspector, unsigned mode) : DataHandler(NAME), owner(inspector), mode(mode) { }
    void handle(DataEvent&,Flow*) override;
private:
    SessionInspector& owner;
    unsigned mode;
};

class SessionModule : public Module
{
public:
    SessionModule();
    bool set(const char*,Value& value,SnortConfig*) override
    {
        if (value.is("snapshot_interval")) settings.interval=value.get_uint32();
        else if (value.is("state_limit")) settings.state_limit=value.get_uint32();
        return true;
    }
    Settings settings;
};

class SessionInspector : public Inspector
{
public:
    explicit SessionInspector(const Settings& value) : settings(value) { }
    void eval(Packet*) override { }
    bool configure(SnortConfig* config) override
    {
        config->set_run_flags(RUN_FLAG__TRACK_ON_SYN);
        DataBus::subscribe_global(intrinsic_pub_key,IntrinsicEventIds::FLOW_STATE_SETUP,new Handler(*this,2),*config);
        DataBus::subscribe_global(intrinsic_pub_key,IntrinsicEventIds::FLOW_STATE_RELOADED,new Handler(*this,2),*config);
        DataBus::subscribe_global(intrinsic_pub_key,IntrinsicEventIds::FINALIZE_PACKET,new Handler(*this,0),*config);
        DataBus::subscribe_global(intrinsic_pub_key,IntrinsicEventIds::FLOW_END,new Handler(*this,1),*config);
        DataBus::subscribe_network(appid_pub_key,AppIdEventIds::ANY_CHANGE,new Handler(*this,0));
        return true;
    }
    void tinit() override
    {
        output();
    }
    void tterm() override
    {
        auto* log=static_cast<TextLog*>(get_thread_specific_data());
        if (log) { TextLog_Term(log);set_thread_specific_data(nullptr); }
    }
    void observe(Flow* flow,const Packet* packet,bool end)
    {
        if (!supported(flow) || !flow->ndr_session_id) return;
        auto* state=static_cast<Evidence*>(flow->get_flow_data(flow_slot));
        if (state && state->identity!=flow->ndr_session_id)
        {
            flow->free_flow_data(flow_slot);state=nullptr;
        }
        bool created=!state;
        if (created) { state=new Evidence(flow->ndr_session_id);flow->set_flow_data(state); }
        if (packet && packet->pkth)
        {
            double time=double(packet->pkth->ts.tv_sec)+double(packet->pkth->ts.tv_usec)/1000000;
            if (!state->first) state->first=time;
            if (time<state->first) state->first=time;
            if (time>state->last) state->last=time;
            if (created && flow->pkt_type==PktType::TCP && packet->ptrs.tcph)
                state->initial_syn=packet->ptrs.tcph->is_syn() && !packet->ptrs.tcph->is_ack();
            if (!packet->is_cooked() && packet->ptrs.ip_api.is_ip())
            {
                state->packet_seen=true;state->packet_time=time;
                state->packet_length=packet->pktlen;state->data_length=packet->dsize;
                state->ttl=packet->ptrs.ip_api.ttl();state->tos=packet->ptrs.ip_api.tos();
                state->ip_proto=unsigned(packet->ptrs.ip_api.proto());state->ip_header_len=packet->ptrs.ip_api.hlen();
                state->ip_id=packet->ptrs.ip_api.id();state->ip_offset=packet->ptrs.ip_api.off();
                state->ip_flags=(packet->ptrs.ip_api.off_w_flags()>>13)&7;
                state->direction=packet->is_from_client()?"to_server":packet->is_from_server()?"to_client":"unknown";
                state->tcp_seen=flow->pkt_type==PktType::TCP && packet->ptrs.tcph;
                state->icmp_seen=packet->ptrs.icmph;
                if (state->icmp_seen)
                {
                    state->icmp_type=unsigned(packet->ptrs.icmph->type);state->icmp_code=unsigned(packet->ptrs.icmph->code);
                }
                if (state->tcp_seen)
                {
                    const auto* tcp=packet->ptrs.tcph;
                    state->tcp_flags=tcp->th_flags;state->tcp_window=tcp->win();
                    state->tcp_seq=tcp->seq();state->tcp_ack=tcp->ack();state->tcp_options=tcp->options_len();
                }
            }
        }
        // A flow predating activation may only be observed at EOF. Do not
        // invent fractional capture timestamps for that case.
        if (!state->last) state->first=state->last=flow->last_data_seen;
        int client=-1,server=-1;
        if (flow->pkt_type==PktType::TCP && flow->session)
        {
            auto* session=static_cast<TcpSession*>(flow->session);
            client=session->client.get_tcp_state();server=session->server.get_tcp_state();
        }
        bool changed=client!=state->client || server!=state->server;
        state->client=client;state->server=server;
        const auto* api=appid_api.get_appid_session_api(*flow);
        std::array<AppId,5> applications{};
        if (api) api->get_app_id(applications[0],applications[1],applications[2],applications[3],applications[4]);
        bool app_changed=applications!=state->applications;
        state->applications=applications;
        const char* event=nullptr;
        if (end) event="end";
        else if (created) event=state->initial_syn?"start":"first_observed";
        else if (changed && state->state_events<settings.state_limit) { event="state";++state->state_events; }
        else if (app_changed && state->app_events<32) { event="application";++state->app_events; }
        else if (state->last-state->published>=settings.interval) event="update";
        if (changed && state->state_events>=settings.state_limit) state->limited=true;
        if (!event) return;
        auto* log=output();
        if (!log) return;
        char source[INET6_ADDRSTRLEN],target[INET6_ADDRSTRLEN];
        flow->client_ip.ntop(source,sizeof(source));flow->server_ip.ntop(target,sizeof(target));
        std::ostringstream json;json<<std::fixed<<std::setprecision(6);
        json<<"{\"engine\":\"snort_session\",\"data\":{\"session_id\":"<<quoted(flow->ndr_session_label())
            <<",\"ts\":"<<state->last<<",\"event\":"<<quoted(event)
            <<",\"first_observed\":"<<state->first<<",\"last_observed\":"<<state->last
            <<",\"src\":"<<quoted(source)<<",\"sport\":"<<flow->client_port
            <<",\"dst\":"<<quoted(target)<<",\"dport\":"<<flow->server_port
            <<",\"proto\":"<<quoted(flow->pkt_type==PktType::TCP?"TCP":flow->pkt_type==PktType::UDP?"UDP":flow->pkt_type==PktType::ICMP?"ICMP":"IP")
            <<",\"client_state\":"<<client<<",\"server_state\":"<<server
            <<",\"initial_syn_observed\":"<<(state->initial_syn?"true":"false")
            <<",\"state_limit_reached\":"<<(state->limited?"true":"false")
            <<",\"orig_pkts\":"<<flow->flowstats.client_pkts<<",\"resp_pkts\":"<<flow->flowstats.server_pkts
            <<",\"orig_wire_bytes\":"<<flow->flowstats.client_bytes<<",\"resp_wire_bytes\":"<<flow->flowstats.server_bytes;
        if (state->packet_seen)
        {
            json<<",\"packet_ts\":"<<state->packet_time<<",\"packet_len\":"<<state->packet_length
                <<",\"data_len\":"<<state->data_length<<",\"packet_direction\":"<<quoted(state->direction)
                <<",\"ip_ttl\":"<<state->ttl<<",\"ip_tos\":"<<state->tos<<",\"ip_id\":"<<state->ip_id
                <<",\"ip_offset\":"<<state->ip_offset<<",\"ip_flags\":"<<state->ip_flags
                <<",\"ip_proto\":"<<state->ip_proto<<",\"ip_header_len\":"<<state->ip_header_len;
            if (state->tcp_seen)
                json<<",\"tcp_flags\":"<<state->tcp_flags<<",\"tcp_window\":"<<state->tcp_window
                    <<",\"tcp_seq\":"<<state->tcp_seq<<",\"tcp_ack\":"<<state->tcp_ack<<",\"tcp_options_len\":"<<state->tcp_options;
            if (state->icmp_seen)json<<",\"icmp_type\":"<<state->icmp_type<<",\"icmp_code\":"<<state->icmp_code;
        }
        static const char* names[]={"service","client","payload","misc","referred"};
        for (unsigned i=0;i<applications.size();++i)
            json<<",\"appid_"<<names[i]<<"_id\":"<<applications[i]<<",\"appid_"<<names[i]<<"\":"
                <<quoted(applications[i]>0?appid_api.get_application_name(applications[i],*flow):nullptr);
        json<<"}}";
        auto line=json.str();TextLog_Write(log,line.data(),int(line.size()));TextLog_NewLine(log);TextLog_Flush(log);
        state->published=state->last;
    }
private:
    TextLog* output()
    {
        // Snort copies Inspector thread storage during configuration reloads
        // and can skip tinit() for the replacement instance. A map keyed by
        // this would lose the inherited handle. Lazy initialization also
        // supports migration from an older plugin without thread storage.
        auto* log=static_cast<TextLog*>(get_thread_specific_data());
        if (!log) { log=TextLog_Init("ndr_session.json",8192,0,false);set_thread_specific_data(log); }
        return log;
    }
    Settings settings;
};

void Handler::handle(DataEvent& event,Flow* flow)
{
    const Packet* packet=event.get_packet();
    if (!flow && packet) flow=packet->flow;
    if (mode==2)
    {
        if (supported(flow)) flow->flags.trigger_finalize_event=true;
        return;
    }
    owner.observe(flow,packet,mode==1);
}
const Parameter parameters[]={
    {"snapshot_interval",Parameter::PT_INT,"10:3600","30","minimum seconds between traffic snapshots"},
    {"state_limit",Parameter::PT_INT,"4:128","32","maximum state transitions recorded per session"},
    {nullptr,Parameter::PT_MAX,nullptr,nullptr,nullptr}
};
SessionModule::SessionModule() : Module(NAME,"bounded TCP lifecycle and OpenAppID observations",parameters) { }
void initialize() { if (!flow_slot) flow_slot=FlowData::create_flow_data_id(); }
Module* module_ctor() { initialize();return new SessionModule; }
void module_dtor(Module* module) { delete module; }
Inspector* inspector_ctor(Module* module) { return new SessionInspector(static_cast<SessionModule*>(module)->settings); }
void inspector_dtor(Inspector* inspector) { delete inspector; }
const InspectApi api={
    {PT_INSPECTOR,sizeof(InspectApi),INSAPI_VERSION,1,PLUGIN_SO_RELOAD,API_OPTIONS,NAME,
     "bounded TCP lifecycle and OpenAppID observations",module_ctor,module_dtor},
    IT_PASSIVE,PROTO_BIT__NONE,nullptr,nullptr,initialize,nullptr,nullptr,nullptr,
    inspector_ctor,inspector_dtor,nullptr,nullptr
};
}
extern "C" {
SO_PUBLIC const BaseApi* snort_plugins[]={&api.base,nullptr};
}
