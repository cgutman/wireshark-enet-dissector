# wireshark-enet-dissector
Wireshark Dissector for the ENet Protocol

To run: Execute wireshark with "-X lua_script:<path to script>" option.

Usage notes:

1) The dissector will add the "enet" protocol (which can be used to filter for just ENet packets).

2) Choose the UDP stream to dissect, choose "Decode As..." and select ENet
