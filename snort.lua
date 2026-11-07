-- Native Snort configuration. Engine files are installed outside the console release.
include '/opt/ips-snort3/3.12.4.0/etc/snort/snort.lua'
include '/etc/snort/home-net.lua'
ips.variables.nets.HOME_NET = HOME_NET
ips.variables.nets.EXTERNAL_NET = EXTERNAL_NET
ips.enable_builtin_rules = true
ips.rules = [[
include /var/lib/snort/rules/snort.rules
include /var/lib/snort/rules/local.rules
include /var/lib/snort/rules/ips-web-hunting.rules
include /var/lib/snort/rules/ips-web-bans.rules
]]
include '/etc/snort/suppress.lua'
daq = { module_dirs = { '/opt/ips-snort3/3.12.4.0/lib/daq' }, snaplen = 65535 }
reject = { }
-- Decoder failures can occur before a flow exists and bypass extractor notices.
alert_json = { file = true, fields = 'seconds timestamp pkt_num gid sid rev msg proto src_addr src_port dst_addr dst_port action priority class' }
appid = { app_detector_dir = '/var/lib/snort/appid' }
if get_module_version('ndr_session', 'inspector') >= 1 then
    ndr_session = { snapshot_interval = 30, state_limit = 32 }
end
-- Keep file identity and hashes, never capture file contents or dump file bytes.
file_policy = { enable_type = true, enable_signature = true, enable_capture = false }
file_inspect.show_data_depth = 0
file_inspect.trace_stream = false
-- Packet loggers are not part of the metadata-only collection profile.
alert_full = nil
log_codecs = nil
log_hext = nil
log_pcap = nil
file_log = nil
file_connector = { { connector = 'ndr', name = 'ndr', direction = 'transmit', text_format = true } }
local common = 'ts uid session_id id.orig_h id.orig_p id.resp_h id.resp_p pkt_num tenant_id '
local notice_fields = common .. 'gid sid rev msg proto action ips_action ids_reason refs'
if get_module_version('extractor', 'inspector') >= 1 then
    notice_fields = notice_fields .. ' alert_suppressed'
end
extractor = {
    formatting = 'json', connector = 'ndr', time = 'unix',
    protocols = {
        { service = 'notice', on_events = 'ips_logging', fields = notice_fields },
        { service = 'weird', on_events = 'builtin', fields = common .. 'gid sid msg proto source' },
        { service = 'conn', on_events = 'eof', fields = common .. 'duration proto service orig_pkts resp_pkts orig_bytes resp_bytes conn_state history' },
        { service = 'http', on_events = 'eot', fields = common .. 'method host uri user_agent referrer origin version status_code status_msg trans_depth request_body_len response_body_len resp_mime_types orig_filenames resp_filenames' },
        { service = 'dns', on_events = 'response', fields = common .. 'proto trans_id query qclass_name qtype qtype_name rcode rcode_name answers TTLs rejected' },
        { service = 'ssl', on_events = 'tls_metadata_event', fields = common .. 'version server_name validation_status subject issuer module_identifier cipher curve' },
        { service = 'ssh', on_events = 'algorithm exchange', fields = common .. 'version direction client.version server.version kex_alg host_key_alg cipher_alg mac_alg compression_alg' },
        { service = 'ftp', on_events = 'request response eot', fields = common .. 'command arg user reply_code reply_msg file_size' },
        { service = 'file', on_events = 'eof', fields = common .. 'filename fuid source analyzers mime_type is_orig seen_bytes total_bytes duration timedout sha256' }
    }
}
