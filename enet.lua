-- Enet 1.3 Protocol Dissector For Wireshark
--
-- Cameron Gutman (aicommander@gmail.com)
-- Licensed under GPLv3
--

-- ENetProtocolHeader
pf_protoheader_peerid = ProtoField.uint16("enet.peerid", "Peer ID", base.HEX)
pf_protoheader_senttime = ProtoField.uint16("enet.senttime", "Sent Time", base.HEX)

-- ENetProtocolCommandHeader
pf_cmdheader = ProtoField.protocol("enet.cmd", "ENet Command")
pf_cmdheader_command = ProtoField.uint8("enet.cmd.command", "Command", base.HEX)
pf_cmdheader_channelid = ProtoField.uint8("enet.cmd.channelid", "Channel ID", base.HEX)
pf_cmdheader_relseqnum = ProtoField.uint16("enet.cmd.relseqnum", "Reliable Sequence Number", base.HEX)

-- ENetProtocolAcknowledge
pf_ack = ProtoField.protocol("enet.ack", "Acknowledge")
pf_ack_recvrelseqnum = ProtoField.uint16("enet.ack.recvrelseqnum", "Received Reliable Sequence Number", base.HEX)
pf_ack_recvsenttime = ProtoField.uint16("enet.ack.recvsenttime", "Received Sent Time", base.HEX)

-- ENetProtocolConnect
pf_conn = ProtoField.protocol("enet.conn", "Connect")
pf_conn_outgoingpeerid = ProtoField.uint16("enet.conn.outgoingpeerid", "Outgoing Peer ID", base.HEX)
pf_conn_incomingsessionid = ProtoField.uint8("enet.conn.incomingsessionid", "Incoming Session ID", base.HEX)
pf_conn_outgoingsessionid = ProtoField.uint8("enet.conn.outgoingsessionid", "Outgoing Session ID", base.HEX)
pf_conn_mtu = ProtoField.uint32("enet.conn.mtu", "MTU", base.HEX)
pf_conn_windowsize = ProtoField.uint32("enet.conn.windowsize", "Window Size", base.HEX)
pf_conn_channelcount = ProtoField.uint32("enet.conn.channelcount", "Channel Count", base.HEX)
pf_conn_incomingbandwidth = ProtoField.uint32("enet.conn.incomingbandwidth", "Incoming Bandwidth", base.HEX)
pf_conn_outgoingbandwidth = ProtoField.uint32("enet.conn.outgoingbandwidth", "Outgoing Bandwidth", base.HEX)
pf_conn_packetthrottleinterval = ProtoField.uint32("enet.conn.packetthrottleinterval", "Packet Throttle Interval", base.HEX)
pf_conn_packetthrottleaccel = ProtoField.uint32("enet.conn.packetthrottleaccel", "Packet Throttle Acceleration", base.HEX)
pf_conn_packetthrottledecel = ProtoField.uint32("enet.conn.packetthrottledecel", "Packet Throttle Deceleration", base.HEX)
pf_conn_connectid = ProtoField.uint32("enet.conn.connectid", "Connect ID", base.HEX)
pf_conn_data = ProtoField.uint32("enet.conn.data", "Data", base.HEX)

-- ENetProtocolVerifyConnect
pf_connverify = ProtoField.protocol("enet.connverify", "Verify Connect")
pf_connverify_outgoingpeerid = ProtoField.uint16("enet.connverify.outgoingpeerid", "Outgoing Peer ID", base.HEX)
pf_connverify_incomingsessionid = ProtoField.uint8("enet.connverify.incomingsessionid", "Incoming Session ID", base.HEX)
pf_connverify_outgoingsessionid = ProtoField.uint8("enet.connverify.outgoingsessionid", "Outgoing Session ID", base.HEX)
pf_connverify_mtu = ProtoField.uint32("enet.connverify.mtu", "MTU", base.HEX)
pf_connverify_windowsize = ProtoField.uint32("enet.connverify.windowsize", "Window Size", base.HEX)
pf_connverify_channelcount = ProtoField.uint32("enet.connverify.channelcount", "Channel Count", base.HEX)
pf_connverify_incomingbandwidth = ProtoField.uint32("enet.connverify.incomingbandwidth", "Incoming Bandwidth", base.HEX)
pf_connverify_outgoingbandwidth = ProtoField.uint32("enet.connverify.outgoingbandwidth", "Outgoing Bandwidth", base.HEX)
pf_connverify_packetthrottleinterval = ProtoField.uint32("enet.connverify.packetthrottleinterval", "Packet Throttle Interval", base.HEX)
pf_connverify_packetthrottleaccel = ProtoField.uint32("enet.connverify.packetthrottleaccel", "Packet Throttle Acceleration", base.HEX)
pf_connverify_packetthrottledecel = ProtoField.uint32("enet.connverify.packetthrottledecel", "Packet Throttle Deceleration", base.HEX)
pf_connverify_connectid = ProtoField.uint32("enet.connverify.connectid", "Connect ID", base.HEX)

-- ENetProtocolBandwidthLimit
pf_bwlimit = ProtoField.protocol("enet.bwlimit", "Bandwidth Limit")
pf_bwlimit_incomingbandwidth = ProtoField.uint32("enet.bwlimit.incomingbandwidth", "Incoming Bandwidth", base.HEX)
pf_bwlimit_outgoingbandwidth = ProtoField.uint32("enet.bwlimit.outgoingbandwidth", "Outgoing Bandwidth", base.HEX)

-- ENetProtocolThrottleConfigure
pf_throttle = ProtoField.protocol("enet.throttle", "Throttle Configure")
pf_throttle_packetthrottleinterval = ProtoField.uint32("enet.throttle.packetthrottleinterval", "Packet Throttle Interval", base.HEX)
pf_throttle_packetthrottleaccel = ProtoField.uint32("enet.throttle.packetthrottleaccel", "Packet Throttle Acceleration", base.HEX)
pf_throttle_packetthrottledecel = ProtoField.uint32("enet.throttle.packetthrottledecel", "Packet Throttle Deceleration", base.HEX)

-- ENetProtocolDisconnect
pf_disconn = ProtoField.protocol("enet.disconn", "Disconnect")
pf_disconn_data = ProtoField.uint32("enet.disconn.data", "Data", base.HEX)

-- ENetProtocolPing
pf_ping = ProtoField.protocol("enet.ping", "Ping")

-- ENetProtocolSendReliable
pf_sendrel = ProtoField.protocol("enet.sendrel", "Send Reliable")
pf_sendrel_datalen = ProtoField.uint16("enet.sendrel.datalen", "Data Length", base.HEX)
pf_sendrel_data = ProtoField.bytes("enet.sendrel.data", "Data")

-- ENetProtocolSendUnreliable
pf_sendunrel = ProtoField.protocol("enet.sendunrel", "Send Unreliable")
pf_sendunrel_unrelseqnum = ProtoField.uint16("enet.sendunrel.unrelseqnum", "Unreliable Sequence Number", base.HEX)
pf_sendunrel_datalen = ProtoField.uint16("enet.sendunrel.datalen", "Data Length", base.HEX)
pf_sendunrel_data = ProtoField.bytes("enet.sendunrel.data", "Data")

-- ENetProtocolSendUnsequenced
pf_sendunseq = ProtoField.protocol("enet.sendunseq", "Send Unsequenced")
pf_sendunseq_unseqgroup = ProtoField.uint16("enet.sendunseq.unseqgroup", "Unsequenced Group", base.HEX)
pf_sendunseq_datalen = ProtoField.uint16("enet.sendunseq.datalen", "Data Length", base.HEX)
pf_sendunseq_data = ProtoField.bytes("enet.sendunseq.data", "Data")

-- ENetProtocolSendFragment
pf_sendfrag = ProtoField.protocol("enet.sendfrag", "Send Fragment")
pf_sendfrag_startseqnum = ProtoField.uint16("enet.sendfrag.startseqnum", "Start Sequence Number", base.HEX)
pf_sendfrag_datalen = ProtoField.uint16("enet.sendfrag.datalen", "Data Length", base.HEX)
pf_sendfrag_fragcount = ProtoField.uint32("enet.sendfrag.fragcount", "Fragment Count", base.HEX)
pf_sendfrag_fragnum = ProtoField.uint32("enet.sendfrag.fragnum", "Fragment Number", base.HEX)
pf_sendfrag_totallen = ProtoField.uint32("enet.sendfrag.totallen", "Total Length", base.HEX)
pf_sendfrag_fragoff = ProtoField.uint32("enet.sendfrag.fragoff", "Fragment Offset", base.HEX)
pf_sendfrag_data = ProtoField.bytes("enet.sendfrag.data", "Data")

p_enet = Proto ("enet", "ENet")
p_enet.fields = {
    pf_protoheader_peerid,
    pf_protoheader_senttime,
    pf_protoheader_command,
    pf_cmdheader,
    pf_cmdheader_command,
    pf_cmdheader_channelid,
    pf_cmdheader_relseqnum,
    pf_ack,
    pf_ack_recvrelseqnum,
    pf_ack_recvsenttime,
    pf_conn,
    pf_conn_outgoingpeerid,
    pf_conn_incomingsessionid,
    pf_conn_outgoingsessionid,
    pf_conn_mtu,
    pf_conn_windowsize,
    pf_conn_channelcount,
    pf_conn_incomingbandwidth,
    pf_conn_outgoingbandwidth,
    pf_conn_packetthrottleinterval,
    pf_conn_packetthrottleaccel,
    pf_conn_packetthrottledecel,
    pf_conn_connectid,
    pf_conn_data,
    pf_connverify,
    pf_connverify_outgoingpeerid,
    pf_connverify_incomingsessionid,
    pf_connverify_outgoingsessionid,
    pf_connverify_mtu,
    pf_connverify_windowsize,
    pf_connverify_channelcount,
    pf_connverify_incomingbandwidth,
    pf_connverify_outgoingbandwidth,
    pf_connverify_packetthrottleinterval,
    pf_connverify_packetthrottleaccel,
    pf_connverify_packetthrottledecel,
    pf_connverify_connectid,
    pf_bwlimit,
    pf_bwlimit_incomingbandwidth,
    pf_bwlimit_outgoingbandwidth,
    pf_throttle,
    pf_throttle_packetthrottleinterval,
    pf_throttle_packetthrottleaccel,
    pf_throttle_packetthrottledecel,
    pf_disconn,
    pf_disconn_data,
    pf_ping,
    pf_sendrel,
    pf_sendrel_datalen,
    pf_sendrel_data,
    pf_sendunrel,
    pf_sendunrel_unrelseqnum,
    pf_sendunrel_datalen,
    pf_sendunrel_data,
    pf_sendunseq,
    pf_sendunseq_unseqgroup,
    pf_sendunseq_datalen,
    pf_sendunseq_data,
    pf_sendfrag,
    pf_sendfrag_startseqnum,
    pf_sendfrag_datalen,
    pf_sendfrag_fragcount,
    pf_sendfrag_fragnum,
    pf_sendfrag_totallen,
    pf_sendfrag_fragoff,
    pf_sendfrag_data
    }

function p_enet.dissector(buf, pkt, root)
    pkt.cols.protocol = p_enet.name
    
    pktsubtree = root:add(p_enet, buf(0))
    i = 0
    
    -- Read the protocol header
    pktsubtree:add(pf_protoheader_peerid, buf(i, 2), buf(i, 2):uint())
    includes_senttime = bit.band(buf(i, 2):uint(), 0x8000)
    i = i + 2
    
    -- Check if protocol header includes senttime
    if includes_senttime ~= 0 then
        pktsubtree:add(pf_protoheader_senttime, buf(i, 2), buf(i, 2):uint())
        i = i + 2
    end
    
    while buf(i):len() > 0 do
        cmdsubtree = pktsubtree:add(pf_cmdheader)

        -- Read the command header
        command = buf(i, 1):uint()
        cmdsubtree:add(pf_cmdheader_command, buf(i, 1), buf(i, 1):uint())
        i = i + 1
        cmdsubtree:add(pf_cmdheader_channelid, buf(i, 1), buf(i, 1):uint())
        i = i + 1
        cmdsubtree:add(pf_cmdheader_relseqnum, buf(i, 2), buf(i, 2):uint())
        i = i + 2
        
        command = bit.band(command, 0xF)
        if command == 1 then
            -- ENetProtocolAcknowledge
            cmdtypesubtree = cmdsubtree:add(pf_ack)
            
            cmdtypesubtree:add(pf_ack_recvrelseqnum, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_ack_recvsenttime, buf(i, 2), buf(i, 2):uint())
            i = i + 2
        elseif command == 2 then
            -- ENetProtocolConnect
            cmdtypesubtree = cmdsubtree:add(pf_conn)
            
            cmdtypesubtree:add(pf_conn_outgoingpeerid, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_conn_incomingsessionid, buf(i, 1), buf(i, 1):uint())
            i = i + 1
            cmdtypesubtree:add(pf_conn_outgoingsessionid, buf(i, 1), buf(i, 1):uint())
            i = i + 1
            cmdtypesubtree:add(pf_conn_mtu, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_windowsize, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_channelcount, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_incomingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_outgoingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_packetthrottleinterval, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_packetthrottleaccel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_packetthrottledecel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_connectid, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_conn_data, buf(i, 4), buf(i, 4):uint())
            i = i + 4
        elseif command == 3 then
            -- ENetProtocolVerifyConnect
            cmdtypesubtree = cmdsubtree:add(pf_connverify)
            
            cmdtypesubtree:add(pf_connverify_outgoingpeerid, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_connverify_incomingsessionid, buf(i, 1), buf(i, 1):uint())
            i = i + 1
            cmdtypesubtree:add(pf_connverify_outgoingsessionid, buf(i, 1), buf(i, 1):uint())
            i = i + 1
            cmdtypesubtree:add(pf_connverify_mtu, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_windowsize, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_channelcount, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_incomingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_outgoingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_packetthrottleinterval, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_packetthrottleaccel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_packetthrottledecel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_connverify_connectid, buf(i, 4), buf(i, 4):uint())
            i = i + 4
        elseif command == 4 then
            -- ENetProtocolDisconnect
            cmdtypesubtree = cmdsubtree:add(pf_disconn)
            
            cmdtypesubtree:add(pf_disconn_data, buf(i, 4), buf(i, 4):uint())
            i = i + 4
        elseif command == 5 then
            -- ENetProtocolPing
            cmdsubtree:add(pf_ping)  
        elseif command == 6 then
            -- ENetProtocolSendReliable
            cmdtypesubtree = cmdsubtree:add(pf_sendrel)
            
            datalen = buf(i, 2):uint()
            cmdtypesubtree:add(pf_sendrel_datalen, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_sendrel_data, buf(i, datalen))
            i = i + datalen
        elseif command == 7 then
            -- ENetProtocolSendUnreliable
            cmdtypesubtree = cmdsubtree:add(pf_sendunrel)
            
            cmdtypesubtree:add(pf_sendunrel_unrelseqnum, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            datalen = buf(i, 2):uint()
            cmdtypesubtree:add(pf_sendunrel_datalen, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_sendunrel_data, buf(i, datalen))
            i = i + datalen
        elseif command == 8 then
            -- ENetProtocolSendFragment
            cmdtypesubtree = cmdsubtree:add(pf_sendfrag)
            
            cmdtypesubtree:add(pf_sendfrag_startseqnum, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            datalen = buf(i, 2):uint()
            cmdtypesubtree:add(pf_sendfrag_datalen, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_sendfrag_fragcount, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_sendfrag_fragnum, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_sendfrag_totallen, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_sendfrag_fragoff, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_sendfrag_data, buf(i, datalen))
            i = i + datalen
        elseif command == 9 then
            -- ENetProtocolSendUnsequenced
            cmdtypesubtree = cmdsubtree:add(pf_sendunseq)
            
            cmdtypesubtree:add(pf_sendunseq_unseqgroup, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            datalen = buf(i, 2):uint()
            cmdtypesubtree:add(pf_sendunseq_datalen, buf(i, 2), buf(i, 2):uint())
            i = i + 2
            cmdtypesubtree:add(pf_sendunseq_data, buf(i, datalen))
            i = i + datalen
        elseif command == 10 then
            -- ENetProtocolBandwidthLimit
            cmdtypesubtree = cmdsubtree:add(pf_bwlimit)
            
            cmdtypesubtree:add(pf_bwlimit_incomingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_bwlimit_outgoingbandwidth, buf(i, 4), buf(i, 4):uint())
            i = i + 4
        elseif command == 11 then
            -- ENetProtocolThrottleConfigure
            cmdtypesubtree = cmdsubtree:add(pf_throttle)
            
            cmdtypesubtree:add(pf_throttle_packetthrottleinterval, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_throttle_packetthrottleaccel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
            cmdtypesubtree:add(pf_throttle_packetthrottledecel, buf(i, 4), buf(i, 4):uint())
            i = i + 4
        elseif command == 12 then
            -- TODO: ENetProtocolSendUnreliableFragment
        end
    end
end

function p_enet.init()
end

-- FIXME: A better way to get ourselves in the UDP dissector list?
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(0, p_enet)
