import pandas as pd

def build_features(flow):

    total_packets = flow.total_fwd_packets + flow.total_bwd_packets
    total_packets = max(total_packets, 1)

    flow_duration = max(flow.flow_duration, 1)

    flow_packets_s = total_packets / (flow_duration / 1_000_000)
    avg_packet_size = flow.flow_bytes_s / total_packets
    packet_length_mean = avg_packet_size

    data = {
        'Destination Port': float(flow.destination_port),
        'Flow Duration': float(flow_duration),
        'Total Fwd Packets': float(flow.total_fwd_packets),
        'Total Backward Packets': float(flow.total_bwd_packets),
        'Flow Bytes/s': float(flow.flow_bytes_s),
        'Flow Packets/s': float(flow_packets_s),
        'Average Packet Size': float(avg_packet_size),
        'Packet Length Mean': float(packet_length_mean)
    }

    df = pd.DataFrame([data])

    return df, flow_packets_s, avg_packet_size