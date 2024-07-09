import argparse
import os
import sys
import json
import re
import datetime

connectivity_event_list_ = ["server_listening",      "connection_started",  "connection_closed",
                            "connection_id_updated", "spin_bit_updated",   "connection_state_updated",
                            "path_assigned",          "mtu_updated"]

quic_event_list_         = ["version_information",     "alpn_information",    "parameters_set",
                            "parameters_restored",     "packet_sent",         "packet_received",
                            "packets_acked",            "datagrams_sent",      "datagrams_received",
                            "datagram_dropped",         "stream_state_updated", "frames_processed",
                            "stream_data_moved",        "datagram_data_moved",  "migration_state_updated",
                            "packet_dropped",            "packet_buffered"]

security_event_list_     = ["key_updated" ,   "key_discarded"]

recovery_event_list_     = ["rec_parameters_set", "rec_metrics_updated", "congestion_state_updated",
                            "loss_timer_updated",  "packet_lost", "marked_for_retransmit", 
                            "ecn_state_updated"]

http_event_list_         = ["http_parameters_set", "http_parameters_restored", "http_stream_type_set",
                            "http_frame_created",  "http_frame_parsed", "push_resolved", "http_setting_parsed"]

qpack_event_list_        = ["qpack_state_updated", "qpack_stream_state_updated", "dynamic_table_updated","headers_encoded",
                            "headers_decoded", "instruction_created", "instruction_parsed"]

packet_type_ = {0: "initial",  1: "0RTT", 2: "handshake" ,
                3: "retry", 4: "short_header", 5: "version_negotiation", 6: "unknown"}

packet_number_namespace_ = {0: "initial", 1: "handshake", 2: "application data", 3: "negotiation"}

packet_type_ = {0: "initial",  1: "0RTT", 2: "handshake" ,
                3: "retry", 4: "short_header", 5: "version_negotiation", 6: "unknown"}

packet_number_namespace_ = {0: "initial", 1: "handshake", 2: "application data", 3: "negotiation"}

send_stream_states_ = ["ready", "send", "data_sent", "reset_sent", "reset_received"]

recv_stream_states_ = ["receive", "size_known", "data_read", "reset_read", "reset_received", "reset_received"]

frame_type_   = ["PADDING", "PING", "ACK", "RESET_STREAM", "STOP_SENDING", "CRYPTO", "NEW_TOKEN",
                 "STREAM", "MAX_DATA", "MAX_STREAM_DATA", "MAX_STREAMS", "DATA_BLOCKED", "STREAM_DATA_BLOCKED", "STREAMS_BLOCKED",
                 "NEW_CONNECTION_ID", "RETIRE_CONNECTION_ID", "PATH_CHALLENGE", "PATH_RESPONSE", "CONNECTION_CLOSE", "HANDSHAKE_DONE",
                 "ACK_MP", "PATH_ABANDON", "PATH_STATUS", "DATAGRAM", "Extension"]

h3_stream_type_ = ["control", "push", "qpack_encode", "qpack_decode", "request", "bytestream", "unknown"]

h3_frame_type_ = ["data", "headers", "bidi_stream_type", "cancel_push", "settings", "push_promise", "goaway", "max_push_id", "unknown"]

last_scid_ = "initcid"

def get_path_id(line):
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "path_id":
            return int(item[1])
    raise ValueError("no path_id")

def parse_line(line):
    event = {}
    event_scid = ""
    pattern = r'\[(.*?)\]'
    matches = re.findall(pattern, line)
    matches = [segment.strip() for segment in matches]
    if(len(matches) != 2):
        return None, event_scid
    time_str = matches[0]
    dt_object = datetime.datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S %f")

    event["time"] = dt_object.timestamp() * 1000
    event["name"] = matches[1]

    if event["name"] in connectivity_event_list_:
        event["name"] = "connectivity:" + event["name"] 
    elif event["name"] in quic_event_list_:
        event["name"] = "quic:" + event["name"] 
    elif event["name"] in security_event_list_:
        event["name"] = "security:" + event["name"]
    elif event["name"] in recovery_event_list_:
        if event["name"] == "rec_parameters_set"  or  event["name"] == "rec_metrics_updated":
            event["name"] = event["name"][4:]
        event["name"] = "recovery:" + event["name"]
    elif event["name"] in http_event_list_:
        if event["name"] == "push_resolved":
            event["name"]  = "h3:push_resolved"
        else:
            event["name"] = "h3:" + event["name"][5:]
    else:
        return None, event_scid
    
    if matches[1] in ["packet_sent", "packet_received", "mtu_updated", "datagrams_sent", "datagrams_received", "packets_acked"]:
        event["path"] = get_path_id(line)
    
    if matches[1] == "packet_sent" or matches[1] == "packet_received":
        event["data"], event_scid = parse_packet_sent_and_recv(line)
        return event, event_scid
    
    if matches[1] == "datagrams_sent" or matches[1] == "datagrams_received":
        event["data"], event_scid = parse_datagrams_sent_or_recv(line)
        return event, event_scid
    
    if matches[1] in  ["server_listening", "connection_started", "connection_close", "connection_state_updated",
                        "path_assigned", "mtu_updated", "alpn_information","parameters_set", "packet_buffered", "packets_acked", "stream_state_updated",
                        "frames_processed", "stream_data_moved", "rec_parameters_set", "rec_metrics_updated", "congestion_state_updated", 
                        "packet_lost", "http_parameters_set", "http_frame_created", "http_frame_parse"]:
        function_name = "parse_" + matches[1]
        func = globals()[function_name]
        (event["data"], event_scid) = func(line)
        return event, event_scid
    else:
        return None, None



def endpoint_events_extraction(file_name, vantagepoint):
    assert(vantagepoint == "server" or vantagepoint == "client")
    conn_events = {
        "vantage_point" :  {"name": vantagepoint + "-view",
                             "type": vantagepoint
        },
        "title": "xquic qlog", 
        "description": "",
        "common_fields": { "ODCID": "", "time_format": "absolute" },
        "events": []
    }
    count = 0
    last_scid_ = "initcid"
    traces_log = {}
    with open(file_name, 'r',encoding='utf-8', errors='ignore') as file:
        for line in file:
            event, scid = parse_line(line)
            if (event is None):
                continue
            if (event is not None) and (scid != last_scid_):
                if count > 0:
                    if(scid in traces_log):
                        traces_log[scid]['events'] += conn_events['events']
                    else:
                        traces_log[last_scid_] = conn_events
                last_scid_ = scid
                conn_events = {
                    "title": "xquic-qlog json: " + vantagepoint, 
                    "description": "",
                    "common_fields": { "ODCID": scid, "time_format": "absolute" },
                    "vantage_point" :  {"name": vantagepoint + "-view",
                             "type": vantagepoint
                    },
                    "events": []
                }
                count = 1
                conn_events["events"].append(event)
            else:
                count += 1
                conn_events["events"].append(event)
    if(count > 1):
        scid = conn_events["common_fields"]["ODCID"]
        if(scid in traces_log):
            traces_log[scid]['events'] += conn_events['events']
        else:
            traces_log[scid] = conn_events
    return list(traces_log.values())


def parse_packet_sent_and_recv(line):
    data = {
            "header": {
              "packet_number": "unknown",
              "packet_type": "unknown"
            },
            "raw": {
              "length": 1280
            }
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "pkt_type"):
            data["header"]["packet_type"] = item[1]
        elif(item[0] == "pkt_num"):
            data["header"]["packet_number"] = int(item[1])
        elif(item[0] == "size"):
            data["raw"]["length"] = int(item[1])
    return (data, event_scid)

def parse_server_listening(line):
    data = {
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        else:
            if item[0].startswith("port"):
                data[item[0]] = int(item[1])
            else:
                data[item[0]] = item[1]
    return (data, event_scid)

def parse_connection_started(line):
     # [2024/05/14 11:34:11 641605] [connection_started] |scid:b59e52a51185db48|xqc_engine_packet_process|local|src_ip:127.0.0.1|src_port:35148|
    data = {
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 0,
            "dst_port": 0
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "src_ip"):
            data["src_ip"] = item[1]
        elif(item[0] == "dst_ip"):
            data["dst_ip"] = item[1]
        elif(item[0] == "src_port"):
            data["src_port"] = int(item[1])
        elif(item[0] == "dst_port"):
            data["dst_port"] = int(item[1])
    return (data, event_scid)

def parse_connection_closed(line):
    # [2024/05/14 11:34:26 672332] [connection_closed] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_conn_destroy|err_code:0|
    data = {
            "connection_code": 0
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "err_code":
            data["connection_code"] = int(item[1])
            break
    return (data, event_scid)

def parse_connection_state_updated(line):
    data = {
            "new": "unknow"
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "new":
            data["new"] = item[1]
            break
    return (data, event_scid)

def parse_path_assigned(line):
    data = {
            "path_id": "unknow"
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "path_id":
            data["path_id"] = item[1]
            break
    return (data, event_scid)


def parse_mtu_updated(line):
    data = {
            "new": 0,
            "done": False
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "new":
            data["path_id"] = int(item[1])
        elif item[0] == "done":
            data["done"] = False
            if int(item[1]):
                data["done"] = True
    return (data, event_scid)

def parse_alpn_information(line):
    #[2024/05/14 11:34:11 548027] [alpn_information] 
    #|scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_ssl_alpn_select_cb|client_alpn:h3 |server_alpn:h3 h3-29 h3-ext transport |selected_alpn:h3|
    data = {
            "server_alpns": [],
            "client_alpns": [],
            "chosen_alpn": {"string_value" : "unknown"}
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "client_alpn":
            alpns = item[1].split(' ')
            for alpn in alpns:
                temp = {"string_value" : alpn}
                data["client_alpns"].append(temp)
        elif item[0] == "server_alpn":
            alpns = item[1].split(' ')
            for alpn in alpns:
                temp = {"string_value" : alpn}
                data["server_alpns"].append(temp)
        elif item[0] == "selected_alpn":
            data["chosen_alpn"]["string_value"] = item[1]
    return (data, event_scid)


def parse_parameters_set(line):
    # [2024/05/14 11:34:11 547473] [tra_parameters_set] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|
    # xqc_conn_create|local|migration:1|max_idle_timeout:120000|max_udp_payload_size:1500|active_connection_id_limit:8|max_data:0|
    data = {
            "max_idle_timeout": 0,
            "max_udp_payload_size": 0,
            "active_connection_id_limit": 0
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] in data.keys:
            data[item[0]] = int(item[1])
    return (data, event_scid)

def parse_packet_buffered(line):
    # [2024/05/14 11:34:11 693524] [packet_buffered] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|
    # xqc_conn_buff_undecrypt_packet_in|pkt_pns:2|pkt_type:4|len:1216|
    data = {
            "header": {
              "packet_number": "unknown",
              "packet_type": "unknown"
            },
            "raw": {
              "length": 1280
            }
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "pkt_type"):
            data["header"]["packet_type"] = packet_type_[int(item[1])]
        elif(item[0] == "pkt_num"):
            data["header"]["packet_number"] = int(item[1])
        elif(item[0] == "len"):
            data["raw"]["length"] = int(item[1])
    return (data, event_scid)

def parse_packets_acked(line):
    # [2024/05/14 11:34:11 642140] [packets_acked] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|
    # xqc_process_ack_frame|pkt_space:0|high:0|low:0|path_id:0|
    data = {
            "packet_number_space": "unknown",
            "packet_numbers": []
    }
    event_scid = "unknown"
    low = 0
    high = -1
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "pkt_space"):
            data["packet_number_space"] = packet_number_namespace_[int(item[1])]
        elif(item[0] == "low"):
            low = int(item[1])
        elif(item[0] == "high"):
            high = int(item[1])
    if(low > high):
        return (None, event_scid)
    for i in range(low, high + 1):
        data["packet_numbers"].append(i)
    return (data, event_scid)

def parse_datagrams_sent_or_recv(line):
    # [2024/05/14 11:34:11 552331] [datagrams_sent] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_send|size:1216|
    data = {
            "raw": {
              "length": 1280
            }
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "size"):
            data["raw"]["length"] = int(item[1])
    return (data, event_scid)

def parse_stream_state_updated(line):
    # [2024/05/14 11:34:11 552613] [stream_state_updated] 
    # |scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_stream_send_state_update|stream_id:3|send_stream|old:0|new:1|
    data = {
           "StreamType" : "bidirectional",
           "new": "unknown",
            "stream_side": "sending"
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) == 1):
            if item[0] == "send_stream":
                data["stream_side"] = "sending"
            if item[0] == "recv_stream":
                data["stream_side"] = "receiving"
        if len(item) != 2:
            continue
        if item[0] == "scid":
            event_scid = item[1]
        if item[0] == "new":
            state = int(item[1])
            if data["stream_side"] == "sending":
                data["new"] = send_stream_states_[state]
            else:
                data["new"] = recv_stream_states_[state]
    return (data, event_scid)


def parse_frames_processed(line):
    data = {
           "frames":[{"frame_type" : "unknow"}]
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    frame_type = -1
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if len(item) == 2 and item[0] == "scid":
            event_scid = item[1]
        if(len(item) == 2 and item[0] == "type"):
            frame_type = int(item[1])
            break
    data["frames"][0]["frame_type"] = frame_type_[frame_type].lower()
    type_str = frame_type_[frame_type]

    if type_str == "PADDING":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "length":
                data["frames"][0]["payload_length"] = int(item[1])
        return (data, event_scid)
    elif type_str == "PING":
        return (data, event_scid)
    
    elif type_str == "ACK":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "ack_range":
                s_clean = item[1].strip("{}")  
                pairs = s_clean.split(", ")  
                result = [list(map(int, pair.split(" - "))) for pair in pairs]
                for i in range(len(result)):
                    if result[i][0] == result[i][1]:
                        result[i] = [result[i][0]]
                data["frames"][0]["acked_ranges"] = result
        return (data, event_scid)
    
    elif type_str == "RESET_STREAM" or type_str == "STOP_SENDING":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "stream_id":
                data["frames"][0]["stream_id"] = int(item[1])
            elif item[0] == "err_code":
                data["frames"][0]["error_code"] = int(item[1])
            elif item[0] == "final_size":
                data["frames"][0]["final_size"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "CRYPTO":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "offset":
                data["frames"][0]["offset"] = int(item[1])
            elif item[0] == "length":
                data["frames"][0]["length"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "NEW_TOKEN":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "token":
                data["frames"][0]["token"] = item[1]
        return (data, event_scid)
    
    elif type_str == "STREAM":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "data_length":
                data["frames"][0]["length"] = int(item[1])
            elif item[0] == "data_offset":
                data["frames"][0]["offset"] = int(item[1])
            elif item[0] == "fin":
                data["frames"][0]["fin"] = False
                if int(item[1]):
                    data["frames"][0]["offset"] = True
        return (data, event_scid)
    
    elif type_str == "MAX_DATA":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "max_data":
                data["frames"][0]["maximum"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "MAX_STREAM_DATA":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "stream_id":
                data["frames"][0]["stream_id"] = int(item[1])
            elif item[0] == "max_stream_data":
                data["frames"][0]["maximum"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "MAX_STREAMS":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "stream_type":
                data["frames"][0]["stream_type"] = item[1]
            elif item[0] == "maximum":
                data["frames"][0]["maximum"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "DATA_BLOCKED":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "limit":
                data["frames"][0]["limit"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "STREAM_DATA_BLOCKED":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "stream_id":
                data["frames"][0]["stream_id"] = int(item[1])
            elif item[0] == "limit":
                data["frames"][0]["limit"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "STREAMS_BLOCKED":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "stream_type":
                data["frames"][0]["stream_type"] = item[1]
            elif item[0] == "limit":
                data["frames"][0]["limit"] = int(item[1])
        return (data, event_scid)
    
    elif type_str == "NEW_CONNECTION_ID":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] in ["sequence_number", "retire_prior_to", "connection_id_length"]:
                data["frames"][0][item[0]] = int(item[1])
            elif item[0] == "connection_id":
                data["frames"][0]["connection_id"] = item[1]
        return (data, event_scid)

    elif type_str == "CONNECTION_CLOSE":
        for i in range(1,len(segments)):
            item = segments[i].split(':')
            item = [i.strip() for i in item]
            if(len(item) != 2):
                continue
            if item[0] == "err_code":
                data["frames"][0]["error_code"] = int(item[1])
        return (data, event_scid)
    else:
        return (data, event_scid)

def parse_stream_data_moved(line):
    # [2024/05/14 11:34:11 547904] [stream_data_moved] |scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_stream_send|ret:-610|stream_id:3|stream_send_offset:0|pkt_type:SHORT_HEADER|buff_1rtt:0|send_data_size:1|offset:0|fin:0|
    # stream_flag:17|conn:0000000002354F7C|conn_state:S_INIT|flag:TICKING TOKEN_OK UPPER_CONN_EXIST INIT_RECVD |from:application|to:transport|
    data = {
           "stream_id" : "unknown",
           "offset": 0,
           "length": 0,
           "from": "unknown",
           "to": "unknown"

    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) == 1):
            continue
        if item[0] == "stream_id":
            data["stream_id"] = int(item[1])
        elif item[0] == "stream_send_offset":
            data["offset"] = int(item[1])
        elif item[0] in ["from", "to"]:
            data[item[0]] = item[1]
        elif item[0] == "send_data_size":
            data["length"] = int(item[1])
        elif item[0] == "scid":
            event_scid = item[1]
        
    return (data, event_scid)


def parse_rec_parameters_set(line):
    data = {}
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        else:
            data[item[0]] = int(item[1])
    return (data, event_scid)

def parse_rec_metrics_updated(line):
    # [2024/05/14 11:34:11 642348] [rec_metrics_updated] 
    # |scid:007cc254f81be8e78d765a2e63339fc99a66320d|xqc_send_ctl_on_ack_received|
    # cwnd:47152|inflight:1384|mode:0|applimit:0|pacing_rate:1477151|bw:13370|srtt:89748|latest_rtt:89748|ctl_rttvar:0|pto_count:89748|min_rtt:6|send:0|lost:0|tlp:29|recv:47152|
    data = {}
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "cwnd":
            data["congestion_window"] = int(item[1])
        elif item[0] == "inflight":
            data["bytes_in_flight"] = int(item[1])
        elif item[0] == "pacing_rate":
            data["pacing_rate"] = int(item[1])
        elif item[0] == "pto_count":
            data["pto_count"] = int(item[1])
        elif item[0] == "ctl_rttvar":
            data["rtt_variance"] = int(item[1])
        elif item[0] == "min_rtt":
            data["min_rtt"] = int(item[1])
        elif item[0] == "latest_rtt":
            data["latest_rtt"] = int(item[1])

    return (data, event_scid)

def parse_congestion_state_updated(line):
    data = {"new" : "unknown"}
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif item[0] == "new_state":
            data["new"] = item[1]
            return (data, event_scid)

def parse_packet_lost(line):
    data = {
            "header": {
              "packet_number": "unknown",
              "packet_type": "unknown"
            }
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "pkt_type"):
            data["header"]["packet_type"] = packet_type_[int(item[1])]
        elif(item[0] == "pkt_num"):
            data["header"]["packet_number"] = int(item[1])
    return (data, event_scid)

def parse_http_parameters_set(line):
    data = {}
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "owner"):
            data["owner"] = item[1]
        else:
            data[item[0]] = int(item[1])
    return (data, event_scid)

def parse_http_stream_type_set(line):
    data = {"stream_id": "unknown",
             "stream_type": "unknown"
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "stream_id"):
            data["stream_id"] = int(item[1])
        elif item[0] == "stream_type":
            data["stream_type"] = h3_stream_type_[int(item[1])]
    return (data, event_scid)

def parse_http_frame_created(line):
    data = {"stream_id": "unknown",
            "frame": {"frame_type": "unknown"}
    }
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    h3_frame_type = "unknown"
    kv = {}
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        if item[0] == "type":
            h3_frame_type = h3_frame_type_[int(item[1])]
        else:
            kv[item[0]] = item[1]
    data["frame"]["frame_type"] =  h3_frame_type
    data["stream_id"] =  kv["stream_id"]
    if h3_frame_type == "data":
        return (data, event_scid)
    elif h3_frame_type == "headers":
        header_list = []
        for i in range(1,len(segments)):
            if segments[i].startswith("{name"):
                match_header = re.findall(r'\{(.*?)\}', segments[i])
                temp_header = {"name": "unknown", "value": "/"}
                temp_header["name"] = match_header[0][5:]
                if len(match_header) == 2:
                    temp_header["value"] = match_header[0][6:]
                header_list.append(temp_header)
        data["frame"]["headers"] = header_list
        return (data, event_scid)

    elif h3_frame_type == "cancel_push" or h3_frame_type == "push_promise":
        data["frame"]["push_id"] = kv["push_id"]
        return (data, event_scid)

    elif h3_frame_type == "settings":
        temp_set = []
        for set_i in ["max_field_section_size", "max_pushes",
                        "qpack_max_table_capacity", "qpack_blocked_streams"]:
            temp_set.append({set_i: int(kv[set_i])})
        data["frame"]["settings"] = temp_set
        return (data, event_scid)
    else:
        return (data, event_scid)

def parse_http_frame_parsed(line):
    data = {}
    event_scid = "unknown"
    segments = line.split('|')
    segments = [segment.strip() for segment in segments]
    assert(len(segments) > 1)
    for i in range(1,len(segments)):
        item = segments[i].split(':')
        item = [i.strip() for i in item]
        if(len(item) != 2):
            continue
        if item[0] == "scid":
            event_scid = item[1]
        elif(item[0] == "stream_id"):
            data["stream_id"] = packet_type_[int(item[1])]
        elif(item[0] == "push_id"):
            data["push_id"] = int(item[1])
    return (data, event_scid)
    

def main():
    global last_scid_
    parser = argparse.ArgumentParser()
    parser.add_argument("--clog", help="xquic client log file")
    parser.add_argument("--slog", help="xquic server log file")
    parser.add_argument("--qlog_path", help="output json file, endswith .json", default="demo_qlog.json")
    args = parser.parse_args()
    if (args.clog is None) and (args.slog is None):
        print("Usage: must provide either --clog or --slog argument")
        sys.exit(1)
    if (args.clog is not None) and (not os.path.isfile(args.clog)):
        print(f"Error: The log '{args.clog}' does not exist.")
        sys.exit(1)
    if (args.slog is not None) and (not os.path.isfile(args.slog)):
        print(f"Error: The log '{args.slog}' does not exist.")
        sys.exit(1)
    if (args.qlog_path is not None) and (not args.qlog_path.endswith(".json")):
        print(f"Error: The qlog_path should endswith .json.")
        sys.exit(1)

    data = { "qlog_version": "0.4",
        "qlog_format": "JSON",
        "title": "xquic qlog",
        "description": "this is a demo qlog json of qlog-draft-07",
        "traces": [] 
    }
    if(args.slog is not None):
        server_traces = endpoint_events_extraction(args.slog, "server")
        data["traces"] += server_traces

    if(args.clog is not None):
        client_traces = endpoint_events_extraction(args.clog, "client")
        data["traces"] += client_traces

    json_output = json.dumps(data, indent=4)
    
    with open(args.qlog_path, 'w') as out_file:
        out_file.write(json_output)


if __name__ == "__main__":
    main()