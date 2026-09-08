import pyshark
from collections import Counter, defaultdict
import ipaddress
import statistics
import json
import os
import subprocess
from datetime import datetime, timezone

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

VERSION = "4.2"


def generate_ai_explanation(report_data):
    """Generate an optional analyst-style explanation from structured findings."""
    if OpenAI is None:
        return None, (
            "The OpenAI Python package is not installed. "
            "Using the built-in explanation instead."
        )

    if not os.getenv("OPENAI_API_KEY"):
        return None, (
            "OPENAI_API_KEY was not found. "
            "Using the built-in explanation instead."
        )

    ai_input = {
        "summary": report_data["summary"],
        "dns": report_data["dns"],
        "port_scans": report_data["port_scans"][:5],
        "correlated_outbound_activity": (
            report_data["correlated_outbound_activity"][:5]
        ),
        "generic_behavior_findings": (
            report_data["generic_behavior_findings"][:10]
        ),
        "hosts": report_data.get("hosts", [])[:10],
        "finding_investigation": report_data.get(
            "finding_investigation",
            {}
        ),
        "automated_explanation": report_data["automated_explanation"]
    }

    instructions = (
        "You are assisting a defensive cybersecurity analyst reviewing "
        "network-traffic findings produced by a rule-based PCAP analyzer. "
        "Use only the structured findings provided. Do not claim that "
        "malware, compromise, or an attack is proven unless the evidence "
        "explicitly proves it. Clearly distinguish observations from "
        "possible interpretations. Give a concise analyst-style explanation "
        "with these sections: Summary, Why It Was Flagged, and Recommended "
        "Defensive Follow-Up. Keep the response under 300 words. Do not "
        "provide offensive instructions."
    )

    try:
        client = OpenAI()
        response = client.responses.create(
            model="gpt-5.6-luna",
            instructions=instructions,
            input=json.dumps(ai_input, indent=2)
        )

        explanation = response.output_text.strip()

        if not explanation:
            return None, (
                "The AI service returned an empty response. "
                "Using the built-in explanation instead."
            )

        return explanation, None

    except Exception as error:
        error_name = type(error).__name__

        if error_name == "RateLimitError":
            message = (
                "AI explanation unavailable because the API request could "
                "not be completed due to quota or rate limits. "
                "Using the built-in explanation instead."
            )
        elif error_name == "AuthenticationError":
            message = (
                "AI explanation unavailable because API authentication "
                "failed. Using the built-in explanation instead."
            )
        elif error_name == "PermissionDeniedError":
            message = (
                "AI explanation unavailable because the API key does not "
                "have the required permission. "
                "Using the built-in explanation instead."
            )
        else:
            message = (
                f"AI explanation unavailable ({error_name}). "
                "Using the built-in explanation instead."
            )

        return None, message



def get_total_packet_count(pcap_file):
    """Return the packet count using Wireshark's capinfos when available."""
    commands = [
        ["capinfos", "-c", "-M", pcap_file],
        [
            r"C:\\Program Files\\Wireshark\\capinfos.exe",
            "-c",
            "-M",
            pcap_file
        ]
    ]

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )

            for line in result.stdout.splitlines():
                if "Number of packets" in line:
                    value = line.split(":", 1)[1].strip()
                    value = value.replace(",", "").replace(" ", "")
                    return int(value)
        except Exception:
            continue

    return None


def analyze_pcap(
    pcap_file=None,
    interactive=True,
    generate_ai=False,
    save_reports=False,
    progress_callback=None
):
    if pcap_file is None:
        pcap_file = input("Enter the path to your PCAP file: ").strip().strip('"')

    print("\nReading PCAP...")

    total_packet_count = get_total_packet_count(pcap_file)

    if progress_callback is not None:
        progress_callback(0, total_packet_count)

    capture = pyshark.FileCapture(pcap_file)

    packet_count = 0
    protocols = Counter()

    ipv4_packets = 0
    ipv6_packets = 0

    flows = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "directions": Counter(),
        "destination_ports": Counter()
    })

    dns_queries = []
    dns_query_counts = Counter()
    dns_query_lengths = []
    dns_query_timestamps = []

    capture_first_seen = None
    capture_last_seen = None

    syn_scan_activity = defaultdict(lambda: {
        "ports": set(),
        "attempts": 0,
        "packets": 0,
        "first_seen": None,
        "last_seen": None
    })

    outbound_host_port_activity = defaultdict(lambda: {
        "destinations": set(),
        "attempts": 0,
        "timestamps": [],
        "destination_counts": Counter()
    })

    host_activity = defaultdict(lambda: {
        "packets_sent": 0,
        "packets_received": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "destination_ips": Counter(),
        "destination_ports": Counter(),
        "protocols": Counter(),
        "dns_queries": Counter(),
        "tcp_syn_attempts": 0
    })


    def is_multicast_or_broadcast(ip):
        try:
            address = ipaddress.ip_address(ip)

            if address.is_multicast:
                return True

            if ip == "255.255.255.255":
                return True

            if isinstance(address, ipaddress.IPv4Address) and ip.endswith(".255"):
                return True

        except Exception:
            pass

        return False


    def is_private_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False


    def calculate_timing_stats(timestamps):
        timestamps = sorted(timestamps)

        if len(timestamps) < 2:
            return {
                "duration": 0,
                "average_interval": 0,
                "median_interval": 0,
                "interval_stdev": 0,
                "coefficient_of_variation": 999
            }

        intervals = []

        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i - 1]

            if interval >= 0:
                intervals.append(interval)

        if not intervals:
            return {
                "duration": 0,
                "average_interval": 0,
                "median_interval": 0,
                "interval_stdev": 0,
                "coefficient_of_variation": 999
            }

        duration = timestamps[-1] - timestamps[0]
        average_interval = sum(intervals) / len(intervals)
        median_interval = statistics.median(intervals)

        if len(intervals) >= 2:
            interval_stdev = statistics.stdev(intervals)
        else:
            interval_stdev = 0

        if average_interval > 0:
            coefficient_of_variation = interval_stdev / average_interval
        else:
            coefficient_of_variation = 999

        return {
            "duration": duration,
            "first_seen": timestamps[0],
            "last_seen": timestamps[-1],
            "average_interval": average_interval,
            "median_interval": median_interval,
            "interval_stdev": interval_stdev,
            "coefficient_of_variation": coefficient_of_variation
        }


    for packet in capture:

        packet_count += 1

        if progress_callback is not None and (
            packet_count == 1
            or packet_count % 500 == 0
        ):
            progress_callback(
                packet_count,
                total_packet_count
            )

        if packet_count % 10000 == 0:
            print(f"Processed {packet_count:,} packets...")

        try:
            protocols[packet.highest_layer] += 1
        except Exception:
            pass

        if hasattr(packet, "ip"):
            ipv4_packets += 1
            source = packet.ip.src
            destination = packet.ip.dst

        elif hasattr(packet, "ipv6"):
            ipv6_packets += 1
            source = packet.ipv6.src
            destination = packet.ipv6.dst

        else:
            source = None
            destination = None

        try:
            packet_timestamp = float(packet.sniff_timestamp)
        except Exception:
            packet_timestamp = None

        if packet_timestamp is not None:
            if capture_first_seen is None or packet_timestamp < capture_first_seen:
                capture_first_seen = packet_timestamp

            if capture_last_seen is None or packet_timestamp > capture_last_seen:
                capture_last_seen = packet_timestamp

        if hasattr(packet, "dns"):
            try:
                if hasattr(packet.dns, "qry_name"):
                    domain = packet.dns.qry_name.lower().rstrip(".")

                    dns_queries.append(domain)
                    dns_query_counts[domain] += 1
                    dns_query_lengths.append(len(domain))

                    if packet_timestamp is not None:
                        dns_query_timestamps.append(packet_timestamp)

                    if source is not None:
                        host_activity[source]["dns_queries"][domain] += 1
            except Exception:
                pass

        if source is None or destination is None:
            continue

        try:
            packet_bytes = int(packet.length)
        except Exception:
            packet_bytes = 0

        try:
            packet_protocol = packet.highest_layer
        except Exception:
            packet_protocol = "UNKNOWN"

        host_activity[source]["packets_sent"] += 1
        host_activity[source]["bytes_sent"] += packet_bytes
        host_activity[source]["destination_ips"][destination] += 1
        host_activity[source]["protocols"][packet_protocol] += 1

        host_activity[destination]["packets_received"] += 1
        host_activity[destination]["bytes_received"] += packet_bytes
        host_activity[destination]["protocols"][packet_protocol] += 1

        try:
            if hasattr(packet, "tcp"):
                transport = "TCP"
                source_port = int(packet.tcp.srcport)
                destination_port = int(packet.tcp.dstport)

            elif hasattr(packet, "udp"):
                transport = "UDP"
                source_port = int(packet.udp.srcport)
                destination_port = int(packet.udp.dstport)

            else:
                continue

        except Exception:
            continue

        host_activity[source]["destination_ports"][destination_port] += 1

        timestamp = packet_timestamp

        if transport == "TCP":

            try:
                flags = int(str(packet.tcp.flags), 16)

                syn_set = bool(flags & 0x02)
                ack_set = bool(flags & 0x10)

                if syn_set and not ack_set:

                    host_activity[source]["tcp_syn_attempts"] += 1

                    if not is_multicast_or_broadcast(destination):

                        scan_key = (
                            source,
                            destination
                        )

                        activity = syn_scan_activity[scan_key]

                        activity["ports"].add(destination_port)
                        activity["attempts"] += 1
                        activity["packets"] += 1

                        if timestamp is not None:

                            if activity["first_seen"] is None:
                                activity["first_seen"] = timestamp
                            elif timestamp < activity["first_seen"]:
                                activity["first_seen"] = timestamp

                            if activity["last_seen"] is None:
                                activity["last_seen"] = timestamp
                            elif timestamp > activity["last_seen"]:
                                activity["last_seen"] = timestamp

                        if (
                            is_private_ip(source)
                            and not is_private_ip(destination)
                        ):

                            host_port_key = (
                                source,
                                destination_port
                            )

                            outbound_activity = outbound_host_port_activity[
                                host_port_key
                            ]

                            outbound_activity["destinations"].add(destination)
                            outbound_activity["attempts"] += 1

                            outbound_activity[
                                "destination_counts"
                            ][destination] += 1

                            if timestamp is not None:
                                outbound_activity[
                                    "timestamps"
                                ].append(timestamp)

            except Exception:
                pass

        endpoint1 = (
            source,
            source_port
        )

        endpoint2 = (
            destination,
            destination_port
        )

        if endpoint1 < endpoint2:
            flow_id = (
                endpoint1,
                endpoint2,
                transport
            )
        else:
            flow_id = (
                endpoint2,
                endpoint1,
                transport
            )

        flow = flows[flow_id]

        flow["packets"] += 1

        try:
            flow["bytes"] += int(packet.length)
        except Exception:
            pass

        if timestamp is not None:

            if flow["first_seen"] is None:
                flow["first_seen"] = timestamp
            elif timestamp < flow["first_seen"]:
                flow["first_seen"] = timestamp

            if flow["last_seen"] is None:
                flow["last_seen"] = timestamp
            elif timestamp > flow["last_seen"]:
                flow["last_seen"] = timestamp

        flow["directions"][
            (source, destination)
        ] += 1

        flow["destination_ports"][
            destination_port
        ] += 1


    capture.close()

    if progress_callback is not None:
        progress_callback(
            packet_count,
            total_packet_count or packet_count
        )


    print("\nAnalysis Complete!")
    print("==================")

    print(f"\nPackets analyzed: {packet_count}")

    print("\nIP Version:")
    print(f"  IPv4 packets: {ipv4_packets}")
    print(f"  IPv6 packets: {ipv6_packets}")

    print("\nProtocols found:")

    for protocol, count in protocols.most_common():
        print(f"  {protocol}: {count}")


    print("\nTop Network Conversations:")
    print("==========================")

    sorted_flows = sorted(
        flows.items(),
        key=lambda x: x[1]["packets"],
        reverse=True
    )

    top_conversations = []

    for flow_id, data in sorted_flows[:20]:

        endpoint1, endpoint2, transport = flow_id

        ip1, port1 = endpoint1
        ip2, port2 = endpoint2

        if (
            data["first_seen"] is not None
            and data["last_seen"] is not None
        ):
            duration = data["last_seen"] - data["first_seen"]
        else:
            duration = 0

        packets_per_second = (
            data["packets"] / duration
            if duration > 0
            else 0
        )

        bytes_per_second = (
            data["bytes"] / duration
            if duration > 0
            else 0
        )

        conversation = {
            "endpoint_1": f"{ip1}:{port1}",
            "endpoint_2": f"{ip2}:{port2}",
            "protocol": transport,
            "packets": data["packets"],
            "bytes": data["bytes"],
            "duration_seconds": round(duration, 2),
            "packets_per_second": round(packets_per_second, 2),
            "bytes_per_second": round(bytes_per_second, 2)
        }

        top_conversations.append(conversation)

        print(
            f"\n  {ip1}:{port1} <-> "
            f"{ip2}:{port2}"
        )

        print(f"  Protocol: {transport}")
        print(f"  Packets: {data['packets']}")
        print(f"  Bytes: {data['bytes']}")
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Packets/sec: {packets_per_second:.2f}")
        print(f"  Bytes/sec: {bytes_per_second:.2f}")


    print("\nDNS Activity:")
    print("=============")

    print(f"Total DNS queries: {len(dns_queries)}")
    print(f"Unique domains: {len(dns_query_counts)}")

    if dns_query_counts:

        print("\nMost requested domains:")

        for domain, count in dns_query_counts.most_common(15):
            print(
                f"  {domain}: "
                f"{count} queries"
            )

    else:
        print("\nNo DNS queries found.")


    # ==========================================================
    # DNS BEHAVIOR ANALYSIS
    # ==========================================================

    print("\nDNS Behavior Analysis:")
    print("======================")

    dns_findings = []

    total_dns_queries = len(dns_queries)
    unique_dns_domains = len(dns_query_counts)

    if dns_query_lengths:
        average_dns_length = (
            sum(dns_query_lengths)
            / len(dns_query_lengths)
        )
    else:
        average_dns_length = 0

    long_dns_queries = [
        domain
        for domain in dns_queries
        if len(domain) >= 60
    ]

    very_long_dns_queries = [
        domain
        for domain in dns_queries
        if len(domain) >= 100
    ]

    long_dns_ratio = (
        len(long_dns_queries) / total_dns_queries
        if total_dns_queries > 0
        else 0
    )

    unique_domain_ratio = (
        unique_dns_domains / total_dns_queries
        if total_dns_queries > 0
        else 0
    )

    top_dns_domain = None
    top_dns_count = 0
    top_dns_ratio = 0

    if dns_query_counts:

        top_dns_domain, top_dns_count = (
            dns_query_counts.most_common(1)[0]
        )

        if total_dns_queries > 0:
            top_dns_ratio = (
                top_dns_count / total_dns_queries
            )


    dns_behavior_score = 0
    dns_reasons = []


    if total_dns_queries >= 10000:

        dns_behavior_score += 20

        dns_reasons.append(
            "Extremely high DNS query volume"
        )

    elif total_dns_queries >= 5000:

        dns_behavior_score += 15

        dns_reasons.append(
            "Very high DNS query volume"
        )

    elif total_dns_queries >= 1500:

        dns_behavior_score += 10

        dns_reasons.append(
            "Elevated DNS query volume"
        )


    if (
        total_dns_queries >= 500
        and unique_dns_domains >= 500
        and unique_domain_ratio >= 0.70
    ):

        dns_behavior_score += 25

        dns_reasons.append(
            "High DNS domain diversity"
        )

    elif (
        total_dns_queries >= 250
        and unique_dns_domains >= 200
        and unique_domain_ratio >= 0.60
    ):

        dns_behavior_score += 15

        dns_reasons.append(
            "Elevated DNS domain diversity"
        )


    if (
        total_dns_queries >= 5000
        and top_dns_count >= 5000
        and top_dns_ratio >= 0.90
    ):

        dns_behavior_score += 40

        dns_reasons.append(
            "Extreme DNS concentration on a single domain"
        )

    elif (
        total_dns_queries >= 1000
        and top_dns_count >= 1000
        and top_dns_ratio >= 0.80
    ):

        dns_behavior_score += 30

        dns_reasons.append(
            "Very high DNS concentration on a single domain"
        )

    elif (
        total_dns_queries >= 500
        and top_dns_count >= 300
        and top_dns_ratio >= 0.60
    ):

        dns_behavior_score += 15

        dns_reasons.append(
            "Elevated DNS concentration on a single domain"
        )


    if len(very_long_dns_queries) >= 20:

        dns_behavior_score += 30

        dns_reasons.append(
            "Many extremely long DNS query names"
        )

    elif (
        len(long_dns_queries) >= 30
        and long_dns_ratio >= 0.10
    ):

        dns_behavior_score += 20

        dns_reasons.append(
            "Frequent unusually long DNS query names"
        )


    if (
        average_dns_length >= 50
        and total_dns_queries >= 100
    ):

        dns_behavior_score += 10

        dns_reasons.append(
            "High average DNS query-name length"
        )


    if dns_behavior_score >= 40:

        dns_findings.append({
            "score": dns_behavior_score,
            "total_queries": total_dns_queries,
            "unique_domains": unique_dns_domains,
            "unique_ratio": unique_domain_ratio,
            "average_length": average_dns_length,
            "long_queries": len(long_dns_queries),
            "very_long_queries": len(very_long_dns_queries),
            "top_domain": top_dns_domain,
            "top_domain_count": top_dns_count,
            "top_domain_ratio": top_dns_ratio,
            "reasons": dns_reasons
        })


    if not dns_findings:

        print(
            "\nNo strong suspicious DNS behavior detected."
        )

    else:

        finding = dns_findings[0]

        print(
            "\nPotential suspicious DNS behavior detected:"
        )

        print(
            f"Total DNS queries: "
            f"{finding['total_queries']}"
        )

        print(
            f"Unique domains: "
            f"{finding['unique_domains']}"
        )

        print(
            f"Unique-domain ratio: "
            f"{finding['unique_ratio'] * 100:.2f}%"
        )

        if finding["top_domain"] is not None:

            print(
                f"Most queried domain: "
                f"{finding['top_domain']}"
            )

            print(
                f"Queries to most common domain: "
                f"{finding['top_domain_count']}"
            )

            print(
                f"Top-domain concentration: "
                f"{finding['top_domain_ratio'] * 100:.2f}%"
            )

        print(
            f"Average query-name length: "
            f"{finding['average_length']:.2f}"
        )

        print(
            f"Long DNS names (60+ chars): "
            f"{finding['long_queries']}"
        )

        print(
            f"Very long DNS names (100+ chars): "
            f"{finding['very_long_queries']}"
        )

        print(
            f"DNS behavior score: "
            f"{finding['score']}/100"
        )

        print("Indicators:")

        for reason in finding["reasons"]:
            print(
                f"  [!] {reason}"
            )

        print(
            "Assessment: SUSPICIOUS DNS BEHAVIOR"
        )

        print(
            "Note: High DNS concentration or volume "
            "can have legitimate causes. DNS findings "
            "should be correlated with other evidence."
        )


    # ==========================================================
    # GENERIC SECURITY BEHAVIOR
    # ==========================================================

    print("\nSecurity Behavior Analysis:")
    print("===========================")

    print("\nAnalyzing network behavior...")

    findings = []

    common_destination_ports = {
        20, 21, 22, 23, 25, 53,
        67, 68, 69,
        80, 110, 123,
        135, 137, 138, 139,
        143, 389, 443, 445,
        546, 547,
        587, 636,
        993, 995,
        1433, 3306, 3389,
        5060, 5061,
        5353,
        7680,
        8080
    }


    for flow_id, data in flows.items():

        endpoint1, endpoint2, transport = flow_id

        ip1, port1 = endpoint1
        ip2, port2 = endpoint2

        if (
            data["first_seen"] is not None
            and data["last_seen"] is not None
        ):
            duration = (
                data["last_seen"]
                - data["first_seen"]
            )
        else:
            duration = 0

        if duration <= 0:
            duration = 0.001

        packets = data["packets"]
        bytes_transferred = data["bytes"]

        packets_per_second = (
            packets / duration
        )

        score = 0
        reasons = []

        multicast_or_broadcast = (
            is_multicast_or_broadcast(ip1)
            or is_multicast_or_broadcast(ip2)
        )

        unusual_destination_ports = {
            port
            for port in data["destination_ports"]
            if (
                port not in common_destination_ports
                and port < 49152
            )
        }

        if (
            unusual_destination_ports
            and packets >= 20
            and not multicast_or_broadcast
        ):

            score += 5

            reasons.append(
                "Uses less-common destination port(s): "
                + ", ".join(
                    map(
                        str,
                        sorted(unusual_destination_ports)
                    )
                )
            )

        if (
            packets >= 1000
            and packets_per_second > 1000
        ):

            score += 20

            reasons.append(
                f"Very high sustained packet rate "
                f"({packets_per_second:.0f} packets/sec)"
            )

        elif (
            packets >= 500
            and packets_per_second > 500
        ):

            score += 10

            reasons.append(
                f"High sustained packet rate "
                f"({packets_per_second:.0f} packets/sec)"
            )

        if bytes_transferred > 100_000_000:

            score += 20

            reasons.append(
                f"Very large data transfer "
                f"({bytes_transferred / 1_000_000:.1f} MB)"
            )

        elif bytes_transferred > 50_000_000:

            score += 10

            reasons.append(
                f"Large data transfer "
                f"({bytes_transferred / 1_000_000:.1f} MB)"
            )

        dhcp_ports = {
            67,
            68,
            546,
            547
        }

        is_dhcp_flow = (
            port1 in dhcp_ports
            or port2 in dhcp_ports
        )

        if (
            len(data["directions"]) == 1
            and packets >= 50
            and not multicast_or_broadcast
            and not is_dhcp_flow
        ):

            score += 10

            reasons.append(
                "Significant traffic observed "
                "in only one direction"
            )

        if score >= 50:
            assessment = "HIGH ATTENTION"

        elif score >= 25:
            assessment = "INVESTIGATE"

        elif score >= 10:
            assessment = "LOW CONCERN"

        else:
            assessment = "LIKELY NORMAL"

        if score >= 10:

            findings.append({
                "score": score,
                "assessment": assessment,
                "ip1": ip1,
                "port1": port1,
                "ip2": ip2,
                "port2": port2,
                "transport": transport,
                "packets": packets,
                "bytes": bytes_transferred,
                "duration": duration,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "reasons": reasons
            })


    # ==========================================================
    # PORT SCAN DETECTION
    # ==========================================================

    print("\nPotential Port Scans:")
    print("=====================")

    scan_findings = []

    for (
        source_ip,
        destination_ip
    ), activity in syn_scan_activity.items():

        all_ports = activity["ports"]

        unique_ports = len(all_ports)

        service_ports = {
            port
            for port in all_ports
            if port < 49152
        }

        unique_service_ports = len(service_ports)

        attempts = activity["attempts"]

        if (
            activity["first_seen"] is not None
            and activity["last_seen"] is not None
        ):
            duration = (
                activity["last_seen"]
                - activity["first_seen"]
            )
        else:
            duration = 0

        if duration <= 0:
            duration = 0.001

        service_ports_per_second = (
            unique_service_ports / duration
        )

        is_scan = False
        scan_strength = None

        if (
            unique_service_ports >= 100
            and attempts >= 100
            and service_ports_per_second >= 0.5
        ):

            is_scan = True
            scan_strength = "STRONG"

        elif (
            unique_service_ports >= 50
            and attempts >= 50
            and service_ports_per_second >= 1.0
        ):

            is_scan = True
            scan_strength = "MODERATE"

        if is_scan:

            scan_findings.append({
                "source": source_ip,
                "destination": destination_ip,
                "unique_ports": unique_ports,
                "service_ports": unique_service_ports,
                "attempts": attempts,
                "packets": activity["packets"],
                "ports": sorted(service_ports),
                "duration": duration,
                "first_seen": activity["first_seen"],
                "last_seen": activity["last_seen"],
                "ports_per_second": service_ports_per_second,
                "strength": scan_strength
            })


    if not scan_findings:

        print("\nNo obvious port scans detected.")

    else:

        scan_findings.sort(
            key=lambda x: x["service_ports"],
            reverse=True
        )

        print(
            f"\nFound {len(scan_findings)} "
            f"potential port scan(s):"
        )

        for scan in scan_findings[:10]:

            print("\n----------------------------------")
            print(f"Source: {scan['source']}")
            print(f"Target: {scan['destination']}")

            print(
                f"Unique service/registered ports: "
                f"{scan['service_ports']}"
            )

            print(
                f"Total unique destination ports: "
                f"{scan['unique_ports']}"
            )

            print(
                f"TCP SYN attempts: "
                f"{scan['attempts']}"
            )

            print(
                f"Packets involved: "
                f"{scan['packets']}"
            )

            print(
                f"Duration: "
                f"{scan['duration']:.2f} seconds"
            )

            print(
                f"Service ports/sec: "
                f"{scan['ports_per_second']:.2f}"
            )

            print("Transport: TCP")

            print(
                "Ports contacted: "
                + ", ".join(
                    map(
                        str,
                        scan["ports"][:30]
                    )
                )
            )

            print(
                f"Scan confidence: "
                f"{scan['strength']}"
            )

            print(
                "Assessment: POTENTIAL PORT SCAN"
            )


    # ==========================================================
    # CORRELATED OUTBOUND ACTIVITY
    # ==========================================================

    print("\nCorrelated Repeated Outbound Activity:")
    print("======================================")

    outbound_findings = []

    common_web_ports = {
        80,
        443
    }

    for (
        source_ip,
        destination_port
    ), activity in outbound_host_port_activity.items():

        attempts = activity["attempts"]

        destination_count = len(
            activity["destinations"]
        )

        timing = calculate_timing_stats(
            activity["timestamps"]
        )

        duration = timing["duration"]
        average_interval = timing["average_interval"]
        median_interval = timing["median_interval"]

        coefficient_of_variation = (
            timing["coefficient_of_variation"]
        )

        evidence_score = 0
        reasons = []

        if attempts >= 5000:

            evidence_score += 35

            reasons.append(
                "Extremely high number of repeated "
                "outbound connection attempts"
            )

        elif attempts >= 1000:

            evidence_score += 25

            reasons.append(
                "Very high number of repeated "
                "outbound connection attempts"
            )

        elif attempts >= 250:

            evidence_score += 10

            reasons.append(
                "High number of repeated "
                "outbound connection attempts"
            )

        if destination_count >= 4:

            evidence_score += 20

            reasons.append(
                f"Same destination port used across "
                f"{destination_count} external IP addresses"
            )

        elif destination_count >= 3:

            evidence_score += 15

            reasons.append(
                f"Same destination port used across "
                f"{destination_count} external IP addresses"
            )

        if (
            attempts >= 50
            and 1 <= average_interval <= 60
            and coefficient_of_variation <= 0.50
        ):

            evidence_score += 20

            reasons.append(
                "Connection timing is relatively regular"
            )

        elif (
            attempts >= 50
            and 1 <= average_interval <= 60
            and coefficient_of_variation <= 1.00
        ):

            evidence_score += 10

            reasons.append(
                "Connection timing shows some regularity"
            )

        if destination_port not in common_destination_ports:

            evidence_score += 10

            reasons.append(
                f"Repeated activity uses less-common "
                f"destination port {destination_port}"
            )

        if destination_port in common_web_ports:

            evidence_score -= 20

            reasons.append(
                "Common web port lowers confidence"
            )

        evidence_score = max(
            evidence_score,
            0
        )

        if evidence_score >= 45:
            strength = "STRONG"

        elif evidence_score >= 30:
            strength = "MODERATE"

        else:
            continue

        outbound_timestamps = sorted(
            activity["timestamps"]
        )

        outbound_first_seen = (
            outbound_timestamps[0]
            if outbound_timestamps
            else None
        )

        outbound_last_seen = (
            outbound_timestamps[-1]
            if outbound_timestamps
            else None
        )

        outbound_findings.append({
            "source": source_ip,
            "port": destination_port,
            "attempts": attempts,
            "destination_count": destination_count,
            "destinations": activity[
                "destination_counts"
            ],
            "duration": duration,
            "first_seen": outbound_first_seen,
            "last_seen": outbound_last_seen,
            "average_interval": average_interval,
            "median_interval": median_interval,
            "coefficient_of_variation": (
                coefficient_of_variation
            ),
            "score": evidence_score,
            "strength": strength,
            "reasons": reasons
        })


    if not outbound_findings:

        print(
            "\nNo strong correlated repeated "
            "outbound patterns detected."
        )

    else:

        outbound_findings.sort(
            key=lambda x: x["score"],
            reverse=True
        )

        print(
            f"\nFound {len(outbound_findings)} "
            f"correlated outbound pattern(s):"
        )

        for finding in outbound_findings[:10]:

            print("\n----------------------------------")

            print(
                f"Source: "
                f"{finding['source']}"
            )

            print(
                f"Destination port: "
                f"{finding['port']}"
            )

            print(
                f"Total TCP SYN attempts: "
                f"{finding['attempts']}"
            )

            print(
                f"External destinations contacted: "
                f"{finding['destination_count']}"
            )

            print(
                f"Observation duration: "
                f"{finding['duration']:.2f} seconds"
            )

            print(
                f"Average interval: "
                f"{finding['average_interval']:.2f} seconds"
            )

            print(
                f"Median interval: "
                f"{finding['median_interval']:.2f} seconds"
            )

            print(
                f"Timing variation score: "
                f"{finding['coefficient_of_variation']:.2f}"
            )

            print(
                f"Behavior score: "
                f"{finding['score']}/100"
            )

            print(
                f"Pattern confidence: "
                f"{finding['strength']}"
            )

            print("Top destinations:")

            for destination, count in (
                finding["destinations"].most_common(5)
            ):

                print(
                    f"  {destination}: "
                    f"{count} attempts"
                )

            print("Indicators:")

            for reason in finding["reasons"]:

                print(
                    f"  [!] {reason}"
                )

            print(
                "Assessment: CORRELATED REPEATED "
                "OUTBOUND ACTIVITY"
            )

            print(
                "Note: This is behavioral evidence only "
                "and does not by itself prove malware."
            )


    if findings:

        findings.sort(
            key=lambda x: x["score"],
            reverse=True
        )

        print(
            f"\nFound {len(findings)} "
            f"flow(s) worth reviewing:"
        )

        for finding in findings[:20]:

            print("\n----------------------------------")

            print(
                f"{finding['ip1']}:"
                f"{finding['port1']} <-> "
                f"{finding['ip2']}:"
                f"{finding['port2']}"
            )

            print(
                f"Protocol: "
                f"{finding['transport']}"
            )

            print(
                f"Risk Score: "
                f"{finding['score']}/100"
            )

            print(
                f"Assessment: "
                f"{finding['assessment']}"
            )

            print(
                f"Packets: "
                f"{finding['packets']}"
            )

            print(
                f"Bytes: "
                f"{finding['bytes'] / 1_000_000:.2f} MB"
            )

            print(
                f"Duration: "
                f"{finding['duration']:.2f} seconds"
            )

            print("Indicators:")

            for reason in finding["reasons"]:
                print(
                    f"  [!] {reason}"
                )

    else:

        print(
            "\nNo significant behavioral "
            "anomalies were detected."
        )


    # ==========================================================
    # HOST INVESTIGATION SUMMARY
    # ==========================================================

    host_summaries = []

    for host_ip, data in host_activity.items():
        host_categories = []
        host_risk_score = 0

        scans_started = [
            scan for scan in scan_findings
            if scan["source"] == host_ip
        ]

        scans_received = [
            scan for scan in scan_findings
            if scan["destination"] == host_ip
        ]

        outbound_from_host = [
            finding for finding in outbound_findings
            if finding["source"] == host_ip
        ]

        related_flow_findings = [
            finding for finding in findings
            if finding["ip1"] == host_ip or finding["ip2"] == host_ip
        ]

        if scans_started:
            host_categories.append("PORT SCAN SOURCE")
            strongest_host_scan = max(
                scans_started,
                key=lambda x: x["service_ports"]
            )

            if strongest_host_scan["strength"] == "STRONG":
                if strongest_host_scan["service_ports"] >= 500:
                    host_risk_score += 60
                else:
                    host_risk_score += 50
            else:
                host_risk_score += 50

        if scans_received:
            host_categories.append("PORT SCAN TARGET")

        if outbound_from_host:
            host_categories.append(
                "CORRELATED REPEATED OUTBOUND ACTIVITY"
            )

            strongest_host_outbound = max(
                outbound_from_host,
                key=lambda x: x["score"]
            )

            if strongest_host_outbound["score"] >= 70:
                host_risk_score += 60
            elif strongest_host_outbound["score"] >= 50:
                host_risk_score += 45
            else:
                host_risk_score += 30

        if related_flow_findings:
            host_categories.append("NETWORK FLOW FINDINGS")

        host_risk_score = min(host_risk_score, 100)

        if host_risk_score >= 75:
            host_assessment = "HIGH RISK"
        elif host_risk_score >= 50:
            host_assessment = "SUSPICIOUS"
        elif host_risk_score >= 25:
            host_assessment = "REVIEW RECOMMENDED"
        else:
            host_assessment = "LIKELY NORMAL"

        top_destinations = [
            {"ip": ip, "packets": count}
            for ip, count in data["destination_ips"].most_common(10)
        ]

        top_destination_ports = [
            {"port": port, "packets": count}
            for port, count in data["destination_ports"].most_common(10)
        ]

        top_dns_queries = [
            {"domain": domain, "queries": count}
            for domain, count in data["dns_queries"].most_common(10)
        ]

        host_summaries.append({
            "ip": host_ip,
            "private": is_private_ip(host_ip),
            "risk_score": host_risk_score,
            "assessment": host_assessment,
            "threat_categories": host_categories,
            "packets_sent": data["packets_sent"],
            "packets_received": data["packets_received"],
            "bytes_sent": data["bytes_sent"],
            "bytes_received": data["bytes_received"],
            "tcp_syn_attempts": data["tcp_syn_attempts"],
            "dns_queries": sum(data["dns_queries"].values()),
            "unique_dns_domains": len(data["dns_queries"]),
            "top_destinations": top_destinations,
            "top_destination_ports": top_destination_ports,
            "top_dns_queries": top_dns_queries,
            "protocols": dict(data["protocols"]),
            "port_scans_started": len(scans_started),
            "port_scans_received": len(scans_received),
            "outbound_findings": len(outbound_from_host),
            "related_flow_findings": len(related_flow_findings)
        })

    host_summaries.sort(
        key=lambda x: (
            x["risk_score"],
            x["packets_sent"] + x["packets_received"]
        ),
        reverse=True
    )

    suspicious_hosts = [
        host for host in host_summaries
        if host["risk_score"] > 0
    ]

    normal_hosts = [
        host for host in host_summaries
        if host["risk_score"] == 0
    ]

    active_normal_hosts = normal_hosts[:3]

    print("\nHost Investigation Summary:")
    print("===========================")
    print(f"Hosts observed: {len(host_summaries)}")
    print(f"Suspicious hosts: {len(suspicious_hosts)}")

    hosts_to_display = suspicious_hosts + active_normal_hosts

    if not hosts_to_display:
        print("\nNo host activity available for display.")

    for host in hosts_to_display:
        print("\n----------------------------------")
        print(f"Host: {host['ip']}")
        print(
            f"Host Risk: {host['risk_score']}/100 "
            f"({host['assessment']})"
        )
        print(f"Packets sent: {host['packets_sent']}")
        print(f"Packets received: {host['packets_received']}")
        print(f"TCP SYN attempts: {host['tcp_syn_attempts']}")
        print(f"DNS queries: {host['dns_queries']}")

        if host["threat_categories"]:
            print(
                "Threat categories: "
                + ", ".join(host["threat_categories"])
            )
        else:
            print("Threat categories: None detected")

    hidden_normal_count = max(
        len(normal_hosts) - len(active_normal_hosts),
        0
    )

    if hidden_normal_count > 0:
        print(
            f"\n{hidden_normal_count} additional likely-normal host(s) "
            "are available in the full report data."
        )

    # ==========================================================
    # OVERALL THREAT SUMMARY
    # ==========================================================

    print("\n==========================================")
    print("           OVERALL THREAT SUMMARY")
    print("==========================================")

    overall_score = 0
    threat_categories = []


    if scan_findings:

        strongest_scan = scan_findings[0]

        if strongest_scan["strength"] == "STRONG":

            if strongest_scan["service_ports"] >= 500:
                overall_score += 60

            else:
                overall_score += 50

        else:
            overall_score += 50

        threat_categories.append(
            "PORT SCAN"
        )


    if outbound_findings:

        strongest_outbound = (
            outbound_findings[0]
        )

        if strongest_outbound["score"] >= 70:
            overall_score += 60

        elif strongest_outbound["score"] >= 50:
            overall_score += 45

        else:
            overall_score += 30

        threat_categories.append(
            "CORRELATED REPEATED OUTBOUND ACTIVITY"
        )


    if dns_findings:

        strongest_dns = dns_findings[0]

        if strongest_dns["score"] >= 70:
            overall_score += 50

        elif strongest_dns["score"] >= 50:
            overall_score += 35

        else:
            overall_score += 25

        threat_categories.append(
            "SUSPICIOUS DNS BEHAVIOR"
        )


    if findings:

        highest_behavior_score = max(
            finding["score"]
            for finding in findings
        )

        overall_score += min(
            highest_behavior_score,
            30
        )

        if highest_behavior_score >= 50:

            threat_categories.append(
                "HIGH-RISK NETWORK BEHAVIOR"
            )

        elif highest_behavior_score >= 25:

            threat_categories.append(
                "SUSPICIOUS NETWORK BEHAVIOR"
            )


    overall_score = min(
        overall_score,
        100
    )


    if overall_score >= 75:
        overall_assessment = "HIGH RISK"

    elif overall_score >= 50:
        overall_assessment = "SUSPICIOUS"

    elif overall_score >= 25:
        overall_assessment = "REVIEW RECOMMENDED"

    else:
        overall_assessment = "LIKELY NORMAL"


    print(
        f"\nOverall Risk Score: "
        f"{overall_score}/100"
    )

    print(
        f"Overall Assessment: "
        f"{overall_assessment}"
    )

    print("\nThreat Categories:")

    if threat_categories:

        for category in threat_categories:
            print(
                f"  [!] {category}"
            )

    else:
        print(
            "  None detected"
        )


    print("\nAutomated Explanation:")

    explanation_lines = []

    if scan_findings:

        strongest_scan = scan_findings[0]

        explanation_lines.append(
            f"The analyzer observed "
            f"{strongest_scan['service_ports']} "
            f"distinct service/registered destination ports "
            f"receiving TCP SYN connection attempts from "
            f"{strongest_scan['source']} against "
            f"{strongest_scan['destination']}."
        )

        explanation_lines.append(
            f"Scan confidence was "
            f"{strongest_scan['strength']}."
        )

        explanation_lines.append(
            "This pattern is consistent with "
            "port-scanning reconnaissance."
        )


    if outbound_findings:

        strongest_outbound = outbound_findings[0]

        explanation_lines.append(
            f"The analyzer observed "
            f"{strongest_outbound['attempts']} "
            f"outbound TCP connection attempts from "
            f"{strongest_outbound['source']} using "
            f"destination port "
            f"{strongest_outbound['port']}."
        )

        explanation_lines.append(
            f"The same destination port was used across "
            f"{strongest_outbound['destination_count']} "
            f"external destination IP addresses."
        )

        explanation_lines.append(
            f"Average connection interval was "
            f"{strongest_outbound['average_interval']:.2f} "
            f"seconds, with a timing variation score of "
            f"{strongest_outbound['coefficient_of_variation']:.2f}."
        )

        explanation_lines.append(
            "Multiple behavioral indicators were combined "
            "before this activity was flagged."
        )

        explanation_lines.append(
            "This pattern warrants investigation but does "
            "not by itself prove malware."
        )


    if dns_findings:

        strongest_dns = dns_findings[0]

        explanation_lines.append(
            f"DNS analysis observed "
            f"{strongest_dns['total_queries']} queries "
            f"covering {strongest_dns['unique_domains']} "
            f"unique domain names."
        )

        explanation_lines.append(
            f"Unique domains represented "
            f"{strongest_dns['unique_ratio'] * 100:.2f}% "
            f"of total DNS queries."
        )

        if strongest_dns["top_domain"] is not None:

            explanation_lines.append(
                f"The most queried domain accounted for "
                f"{strongest_dns['top_domain_ratio'] * 100:.2f}% "
                f"of all DNS queries."
            )

        explanation_lines.append(
            f"DNS behavior score was "
            f"{strongest_dns['score']}/100."
        )

        explanation_lines.append(
            "Unusual DNS concentration or volume can be "
            "associated with automated activity, but DNS "
            "evidence should be correlated with other "
            "network behavior."
        )


    if not explanation_lines:

        if findings:

            explanation_lines.append(
                "No strong TCP SYN port scan, correlated "
                "repeated outbound pattern, or suspicious "
                "DNS behavior was detected."
            )

            explanation_lines.append(
                "Some individual flows showed behavioral "
                "characteristics worth reviewing."
            )

        else:

            explanation_lines.append(
                "No strong TCP SYN port-scan pattern, "
                "correlated repeated outbound pattern, "
                "suspicious DNS behavior, or significant "
                "network anomaly was detected."
            )


    for line in explanation_lines:
        print(f"  {line}")


    # ==========================================================
    # STRUCTURED FINDING EVIDENCE
    # ==========================================================

    def timestamp_to_iso(timestamp):
        if timestamp is None:
            return None

        try:
            return datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc
            ).isoformat(timespec="milliseconds")
        except Exception:
            return None


    def risk_assessment(score):
        if score >= 75:
            return "HIGH RISK"
        if score >= 50:
            return "SUSPICIOUS"
        if score >= 25:
            return "REVIEW RECOMMENDED"
        return "LIKELY NORMAL"


    structured_findings = []

    # Port scan evidence
    for number, scan in enumerate(
        scan_findings,
        start=1
    ):
        if scan["strength"] == "STRONG":
            if scan["service_ports"] >= 500:
                finding_score = 60
            else:
                finding_score = 50
        else:
            finding_score = 50

        indicators = [
            (
                f"{scan['service_ports']} distinct service/registered "
                "destination ports received initial TCP SYN attempts"
            ),
            (
                f"{scan['attempts']} TCP SYN connection attempts were "
                "observed"
            ),
            (
                f"Service-port contact rate was "
                f"{scan['ports_per_second']:.2f} ports/sec"
            ),
            f"Detector confidence was {scan['strength']}"
        ]

        structured_findings.append({
            "finding_id": f"SCAN-{number:03d}",
            "type": "PORT SCAN",
            "title": "Potential TCP SYN Port Scan",
            "risk_score": finding_score,
            "assessment": risk_assessment(finding_score),
            "confidence": scan["strength"],
            "source": scan["source"],
            "target": scan["destination"],
            "protocol": "TCP",
            "destination_port": None,
            "related_hosts": [
                {
                    "ip": scan["source"],
                    "role": "SOURCE"
                },
                {
                    "ip": scan["destination"],
                    "role": "TARGET"
                }
            ],
            "timing": {
                "first_seen_epoch": scan["first_seen"],
                "last_seen_epoch": scan["last_seen"],
                "first_seen_utc": timestamp_to_iso(
                    scan["first_seen"]
                ),
                "last_seen_utc": timestamp_to_iso(
                    scan["last_seen"]
                ),
                "duration_seconds": round(
                    scan["duration"],
                    2
                )
            },
            "evidence": [
                {
                    "name": "TCP SYN attempts",
                    "value": scan["attempts"]
                },
                {
                    "name": "Unique destination ports",
                    "value": scan["unique_ports"]
                },
                {
                    "name": "Service/registered ports",
                    "value": scan["service_ports"]
                },
                {
                    "name": "Service ports per second",
                    "value": round(
                        scan["ports_per_second"],
                        2
                    )
                }
            ],
            "indicators": indicators,
            "details": {
                "ports_contacted": scan["ports"][:100]
            },
            "summary": (
                f"{scan['source']} contacted "
                f"{scan['service_ports']} service/registered ports on "
                f"{scan['destination']} using initial TCP SYN attempts."
            ),
            "defensive_note": (
                "This pattern is consistent with scanning behavior, but "
                "the finding alone does not prove compromise."
            )
        })

    # Correlated repeated outbound evidence
    for number, finding in enumerate(
        outbound_findings,
        start=1
    ):
        top_destinations = [
            {
                "ip": destination,
                "attempts": count
            }
            for destination, count in finding[
                "destinations"
            ].most_common(10)
        ]

        related_hosts = [
            {
                "ip": finding["source"],
                "role": "SOURCE"
            }
        ]

        related_hosts.extend(
            {
                "ip": item["ip"],
                "role": "DESTINATION"
            }
            for item in top_destinations[:5]
        )

        structured_findings.append({
            "finding_id": f"OUTBOUND-{number:03d}",
            "type": "CORRELATED REPEATED OUTBOUND ACTIVITY",
            "title": "Correlated Repeated Outbound Activity",
            "risk_score": finding["score"],
            "assessment": risk_assessment(
                finding["score"]
            ),
            "confidence": finding["strength"],
            "source": finding["source"],
            "target": None,
            "protocol": "TCP",
            "destination_port": finding["port"],
            "related_hosts": related_hosts,
            "timing": {
                "first_seen_epoch": finding["first_seen"],
                "last_seen_epoch": finding["last_seen"],
                "first_seen_utc": timestamp_to_iso(
                    finding["first_seen"]
                ),
                "last_seen_utc": timestamp_to_iso(
                    finding["last_seen"]
                ),
                "duration_seconds": round(
                    finding["duration"],
                    2
                )
            },
            "evidence": [
                {
                    "name": "TCP SYN attempts",
                    "value": finding["attempts"]
                },
                {
                    "name": "External destinations",
                    "value": finding["destination_count"]
                },
                {
                    "name": "Destination port",
                    "value": finding["port"]
                },
                {
                    "name": "Average interval seconds",
                    "value": round(
                        finding["average_interval"],
                        2
                    )
                },
                {
                    "name": "Timing variation score",
                    "value": round(
                        finding["coefficient_of_variation"],
                        2
                    )
                }
            ],
            "indicators": list(finding["reasons"]),
            "details": {
                "top_destinations": top_destinations
            },
            "summary": (
                f"{finding['source']} made {finding['attempts']} initial "
                f"TCP connection attempts to destination port "
                f"{finding['port']} across "
                f"{finding['destination_count']} external IP addresses."
            ),
            "defensive_note": (
                "Repeated outbound behavior can have legitimate or "
                "automated causes and should be correlated with other "
                "network evidence."
            )
        })

    # Suspicious DNS evidence. Keep this capture-level unless a host can be
    # supported directly by the observed DNS query counts.
    for number, finding in enumerate(
        dns_findings,
        start=1
    ):
        dns_source_counts = []

        for host_ip, host_data in host_activity.items():
            host_dns_total = sum(
                host_data["dns_queries"].values()
            )

            if host_dns_total > 0:
                dns_source_counts.append(
                    (host_ip, host_dns_total)
                )

        dns_source_counts.sort(
            key=lambda item: item[1],
            reverse=True
        )

        top_dns_sources = [
            {
                "ip": host_ip,
                "queries": query_count
            }
            for host_ip, query_count in dns_source_counts[:10]
        ]

        related_hosts = [
            {
                "ip": item["ip"],
                "role": "DNS SOURCE"
            }
            for item in top_dns_sources[:5]
        ]

        dns_first_seen = (
            min(dns_query_timestamps)
            if dns_query_timestamps
            else None
        )

        dns_last_seen = (
            max(dns_query_timestamps)
            if dns_query_timestamps
            else None
        )

        dns_duration = (
            dns_last_seen - dns_first_seen
            if dns_first_seen is not None
            and dns_last_seen is not None
            else 0
        )

        structured_findings.append({
            "finding_id": f"DNS-{number:03d}",
            "type": "SUSPICIOUS DNS BEHAVIOR",
            "title": "Suspicious DNS Behavior",
            "risk_score": finding["score"],
            "assessment": risk_assessment(
                finding["score"]
            ),
            "confidence": None,
            "source": None,
            "target": None,
            "protocol": "DNS",
            "destination_port": 53,
            "related_hosts": related_hosts,
            "timing": {
                "first_seen_epoch": dns_first_seen,
                "last_seen_epoch": dns_last_seen,
                "first_seen_utc": timestamp_to_iso(
                    dns_first_seen
                ),
                "last_seen_utc": timestamp_to_iso(
                    dns_last_seen
                ),
                "duration_seconds": round(
                    dns_duration,
                    2
                )
            },
            "evidence": [
                {
                    "name": "Total DNS queries",
                    "value": finding["total_queries"]
                },
                {
                    "name": "Unique domains",
                    "value": finding["unique_domains"]
                },
                {
                    "name": "Unique-domain ratio percent",
                    "value": round(
                        finding["unique_ratio"] * 100,
                        2
                    )
                },
                {
                    "name": "Top-domain concentration percent",
                    "value": round(
                        finding["top_domain_ratio"] * 100,
                        2
                    )
                },
                {
                    "name": "Average query-name length",
                    "value": round(
                        finding["average_length"],
                        2
                    )
                }
            ],
            "indicators": list(finding["reasons"]),
            "details": {
                "top_domain": finding["top_domain"],
                "top_domain_queries": finding[
                    "top_domain_count"
                ],
                "long_dns_names": finding["long_queries"],
                "very_long_dns_names": finding[
                    "very_long_queries"
                ],
                "top_dns_sources": top_dns_sources
            },
            "summary": (
                f"The capture contained {finding['total_queries']} DNS "
                f"queries across {finding['unique_domains']} unique "
                "domains with a DNS behavior score of "
                f"{finding['score']}/100."
            ),
            "defensive_note": (
                "DNS evidence is capture-level unless host attribution is "
                "directly supported by observed query counts."
            )
        })

    # Supporting generic flow evidence. This uses the existing flow findings
    # without changing the detector or its thresholds.
    for number, finding in enumerate(
        findings[:20],
        start=1
    ):
        structured_findings.append({
            "finding_id": f"FLOW-{number:03d}",
            "type": "NETWORK FLOW FINDING",
            "title": "Network Flow Behavior Finding",
            "risk_score": finding["score"],
            "assessment": risk_assessment(
                finding["score"]
            ),
            "confidence": None,
            "source": finding["ip1"],
            "target": finding["ip2"],
            "protocol": finding["transport"],
            "destination_port": None,
            "related_hosts": [
                {
                    "ip": finding["ip1"],
                    "role": "ENDPOINT"
                },
                {
                    "ip": finding["ip2"],
                    "role": "ENDPOINT"
                }
            ],
            "timing": {
                "first_seen_epoch": finding["first_seen"],
                "last_seen_epoch": finding["last_seen"],
                "first_seen_utc": timestamp_to_iso(
                    finding["first_seen"]
                ),
                "last_seen_utc": timestamp_to_iso(
                    finding["last_seen"]
                ),
                "duration_seconds": round(
                    finding["duration"],
                    2
                )
            },
            "evidence": [
                {
                    "name": "Packets",
                    "value": finding["packets"]
                },
                {
                    "name": "Bytes",
                    "value": finding["bytes"]
                },
                {
                    "name": "Original flow assessment",
                    "value": finding["assessment"]
                }
            ],
            "indicators": list(finding["reasons"]),
            "details": {
                "endpoint_1": (
                    f"{finding['ip1']}:{finding['port1']}"
                ),
                "endpoint_2": (
                    f"{finding['ip2']}:{finding['port2']}"
                )
            },
            "summary": (
                f"{finding['transport']} flow between "
                f"{finding['ip1']}:{finding['port1']} and "
                f"{finding['ip2']}:{finding['port2']} produced a "
                f"behavior score of {finding['score']}/100."
            ),
            "defensive_note": (
                "Generic flow findings are supporting behavioral evidence "
                "and should be interpreted with the higher-confidence "
                "detectors when available."
            )
        })

    structured_findings.sort(
        key=lambda finding: (
            finding["risk_score"],
            finding["finding_id"]
        ),
        reverse=True
    )

    finding_type_counts = Counter(
        finding["type"]
        for finding in structured_findings
    )

    finding_investigation = {
        "total_findings": len(structured_findings),
        "review_priority_findings": sum(
            1
            for finding in structured_findings
            if finding["risk_score"] >= 25
        ),
        "type_counts": dict(finding_type_counts),
        "findings": structured_findings
    }

    capture_duration = (
        capture_last_seen - capture_first_seen
        if capture_first_seen is not None
        and capture_last_seen is not None
        else 0
    )

    capture_timing = {
        "first_seen_epoch": capture_first_seen,
        "last_seen_epoch": capture_last_seen,
        "first_seen_utc": timestamp_to_iso(
            capture_first_seen
        ),
        "last_seen_utc": timestamp_to_iso(
            capture_last_seen
        ),
        "duration_seconds": round(
            capture_duration,
            2
        )
    }

    print("\nFinding Investigation Backend:")
    print("==============================")
    print(
        f"Structured findings prepared: "
        f"{len(structured_findings)}"
    )
    print(
        f"Review-priority findings: "
        f"{finding_investigation['review_priority_findings']}"
    )


    # ==========================================================
    # REPORT EXPORT
    # ==========================================================

    report_data = {
        "analyzer": {
            "name": "AI PCAP Security Analyzer",
            "version": VERSION,
            "analysis_time": datetime.now().isoformat(
                timespec="seconds"
            ),
            "pcap_file": os.path.basename(pcap_file)
        },

        "summary": {
            "packets_analyzed": packet_count,
            "ipv4_packets": ipv4_packets,
            "ipv6_packets": ipv6_packets,
            "protocols": dict(protocols),
            "overall_risk_score": overall_score,
            "overall_assessment": overall_assessment,
            "threat_categories": threat_categories,
            "capture_timing": capture_timing
        },

        "dns": {
            "total_queries": total_dns_queries,
            "unique_domains": unique_dns_domains,
            "unique_domain_ratio_percent": round(
                unique_domain_ratio * 100,
                2
            ),
            "top_domains": [
                {
                    "domain": domain,
                    "queries": count
                }
                for domain, count in dns_query_counts.most_common(15)
            ],
            "behavior_score": dns_behavior_score,
            "suspicious": bool(dns_findings),
            "indicators": dns_reasons
        },

        "port_scans": [
            {
                "source": scan["source"],
                "target": scan["destination"],
                "service_ports": scan["service_ports"],
                "total_destination_ports": scan["unique_ports"],
                "tcp_syn_attempts": scan["attempts"],
                "duration_seconds": round(
                    scan["duration"],
                    2
                ),
                "service_ports_per_second": round(
                    scan["ports_per_second"],
                    2
                ),
                "confidence": scan["strength"]
            }
            for scan in scan_findings
        ],

        "correlated_outbound_activity": [
            {
                "source": finding["source"],
                "destination_port": finding["port"],
                "tcp_syn_attempts": finding["attempts"],
                "external_destinations": finding[
                    "destination_count"
                ],
                "duration_seconds": round(
                    finding["duration"],
                    2
                ),
                "average_interval_seconds": round(
                    finding["average_interval"],
                    2
                ),
                "median_interval_seconds": round(
                    finding["median_interval"],
                    2
                ),
                "timing_variation_score": round(
                    finding["coefficient_of_variation"],
                    2
                ),
                "behavior_score": finding["score"],
                "confidence": finding["strength"],
                "indicators": finding["reasons"]
            }
            for finding in outbound_findings
        ],

        "generic_behavior_findings": [
            {
                "endpoint_1": (
                    f"{finding['ip1']}:{finding['port1']}"
                ),
                "endpoint_2": (
                    f"{finding['ip2']}:{finding['port2']}"
                ),
                "protocol": finding["transport"],
                "risk_score": finding["score"],
                "assessment": finding["assessment"],
                "packets": finding["packets"],
                "bytes": finding["bytes"],
                "duration_seconds": round(
                    finding["duration"],
                    2
                ),
                "indicators": finding["reasons"]
            }
            for finding in findings[:20]
        ],

        "top_network_conversations": top_conversations,

        "hosts": host_summaries,

        "finding_investigation": finding_investigation,

        "automated_explanation": explanation_lines
    }


    print("\nOptional AI Explanation:")
    print("========================")

    if interactive:
        use_ai = input(
            "Generate an AI analyst explanation? (y/n): "
        ).strip().lower()
    else:
        use_ai = "y" if generate_ai else "n"

    ai_explanation = None

    if use_ai in {"y", "yes"}:
        print("\nRequesting AI explanation...")

        ai_explanation, ai_error = generate_ai_explanation(
            report_data
        )

        if ai_explanation:
            print("\nAI Analyst Explanation:")
            print("=======================")
            print(ai_explanation)
        else:
            print(f"\n{ai_error}")

    else:
        print("AI explanation skipped.")

    report_data["ai_explanation"] = {
        "requested": use_ai in {"y", "yes"},
        "generated": bool(ai_explanation),
        "text": ai_explanation
    }

    if interactive:
        save_reports_choice = input(
            "\nSave report files? (y/n): "
        ).strip().lower()
    else:
        save_reports_choice = "y" if save_reports else "n"

    if save_reports_choice in {"y", "yes"}:
        pcap_directory = os.path.dirname(
            os.path.abspath(pcap_file)
        )

        pcap_filename = os.path.basename(pcap_file)

        pcap_name_without_extension = os.path.splitext(
            pcap_filename
        )[0]

        txt_report_path = os.path.join(
            pcap_directory,
            f"{pcap_name_without_extension}_security_report.txt"
        )

        json_report_path = os.path.join(
            pcap_directory,
            f"{pcap_name_without_extension}_security_report.json"
        )


        with open(
            json_report_path,
            "w",
            encoding="utf-8"
        ) as json_file:

            json.dump(
                report_data,
                json_file,
                indent=4
            )


        with open(
            txt_report_path,
            "w",
            encoding="utf-8"
        ) as txt_file:

            txt_file.write(
                "AI PCAP SECURITY ANALYZER REPORT\n"
            )

            txt_file.write(
                "================================\n\n"
            )

            txt_file.write(
                f"Analyzer Version: {VERSION}\n"
            )

            txt_file.write(
                f"Analysis Time: "
                f"{report_data['analyzer']['analysis_time']}\n"
            )

            txt_file.write(
                f"PCAP File: {pcap_filename}\n\n"
            )

            txt_file.write(
                "OVERALL THREAT SUMMARY\n"
            )

            txt_file.write(
                "======================\n"
            )

            txt_file.write(
                f"Risk Score: {overall_score}/100\n"
            )

            txt_file.write(
                f"Assessment: {overall_assessment}\n\n"
            )

            txt_file.write(
                "Threat Categories:\n"
            )

            if threat_categories:

                for category in threat_categories:
                    txt_file.write(
                        f"  - {category}\n"
                    )

            else:
                txt_file.write(
                    "  - None detected\n"
                )

            txt_file.write("\n")

            txt_file.write(
                "TRAFFIC SUMMARY\n"
            )

            txt_file.write(
                "===============\n"
            )

            txt_file.write(
                f"Packets analyzed: {packet_count}\n"
            )

            txt_file.write(
                f"IPv4 packets: {ipv4_packets}\n"
            )

            txt_file.write(
                f"IPv6 packets: {ipv6_packets}\n\n"
            )

            txt_file.write(
                "Protocols:\n"
            )

            for protocol, count in protocols.most_common():
                txt_file.write(
                    f"  {protocol}: {count}\n"
                )

            txt_file.write("\n")

            txt_file.write(
                "DNS ANALYSIS\n"
            )

            txt_file.write(
                "============\n"
            )

            txt_file.write(
                f"Total DNS queries: {total_dns_queries}\n"
            )

            txt_file.write(
                f"Unique domains: {unique_dns_domains}\n"
            )

            txt_file.write(
                f"Unique-domain ratio: "
                f"{unique_domain_ratio * 100:.2f}%\n"
            )

            txt_file.write(
                f"DNS behavior score: "
                f"{dns_behavior_score}/100\n"
            )

            if dns_findings:
                txt_file.write(
                    "Assessment: SUSPICIOUS DNS BEHAVIOR\n"
                )

                txt_file.write(
                    "Indicators:\n"
                )

                for reason in dns_reasons:
                    txt_file.write(
                        f"  - {reason}\n"
                    )

            else:
                txt_file.write(
                    "Assessment: No strong suspicious "
                    "DNS behavior detected\n"
                )

            txt_file.write("\n")

            txt_file.write(
                "PORT SCAN ANALYSIS\n"
            )

            txt_file.write(
                "==================\n"
            )

            if scan_findings:

                for scan in scan_findings:

                    txt_file.write(
                        f"Source: {scan['source']}\n"
                    )

                    txt_file.write(
                        f"Target: {scan['destination']}\n"
                    )

                    txt_file.write(
                        f"Service ports contacted: "
                        f"{scan['service_ports']}\n"
                    )

                    txt_file.write(
                        f"TCP SYN attempts: "
                        f"{scan['attempts']}\n"
                    )

                    txt_file.write(
                        f"Duration: "
                        f"{scan['duration']:.2f} seconds\n"
                    )

                    txt_file.write(
                        f"Confidence: "
                        f"{scan['strength']}\n\n"
                    )

            else:
                txt_file.write(
                    "No obvious port scans detected.\n\n"
                )

            txt_file.write(
                "CORRELATED OUTBOUND ACTIVITY\n"
            )

            txt_file.write(
                "============================\n"
            )

            if outbound_findings:

                for finding in outbound_findings:

                    txt_file.write(
                        f"Source: {finding['source']}\n"
                    )

                    txt_file.write(
                        f"Destination port: "
                        f"{finding['port']}\n"
                    )

                    txt_file.write(
                        f"TCP SYN attempts: "
                        f"{finding['attempts']}\n"
                    )

                    txt_file.write(
                        f"External destinations: "
                        f"{finding['destination_count']}\n"
                    )

                    txt_file.write(
                        f"Behavior score: "
                        f"{finding['score']}/100\n"
                    )

                    txt_file.write(
                        f"Confidence: "
                        f"{finding['strength']}\n"
                    )

                    txt_file.write(
                        "Indicators:\n"
                    )

                    for reason in finding["reasons"]:
                        txt_file.write(
                            f"  - {reason}\n"
                        )

                    txt_file.write("\n")

            else:

                txt_file.write(
                    "No strong correlated repeated outbound "
                    "patterns detected.\n\n"
                )

            txt_file.write(
                "HOST INVESTIGATION SUMMARY\n"
            )

            txt_file.write(
                "==========================\n"
            )

            txt_file.write(
                f"Hosts observed: {len(host_summaries)}\n"
            )

            txt_file.write(
                f"Suspicious hosts: {len(suspicious_hosts)}\n\n"
            )

            for host in hosts_to_display:
                txt_file.write(
                    f"Host: {host['ip']}\n"
                )
                txt_file.write(
                    f"Risk: {host['risk_score']}/100 "
                    f"({host['assessment']})\n"
                )
                txt_file.write(
                    f"Packets sent: {host['packets_sent']}\n"
                )
                txt_file.write(
                    f"Packets received: {host['packets_received']}\n"
                )
                txt_file.write(
                    f"TCP SYN attempts: {host['tcp_syn_attempts']}\n"
                )
                txt_file.write(
                    f"DNS queries: {host['dns_queries']}\n"
                )

                if host["threat_categories"]:
                    txt_file.write(
                        "Threat categories: "
                        + ", ".join(host["threat_categories"])
                        + "\n"
                    )
                else:
                    txt_file.write(
                        "Threat categories: None detected\n"
                    )

                if host["top_destinations"]:
                    txt_file.write("Top destinations:\n")
                    for destination in host["top_destinations"][:5]:
                        txt_file.write(
                            f"  - {destination['ip']}: "
                            f"{destination['packets']} packets\n"
                        )

                if host["top_destination_ports"]:
                    txt_file.write("Top destination ports:\n")
                    for port in host["top_destination_ports"][:5]:
                        txt_file.write(
                            f"  - {port['port']}: "
                            f"{port['packets']} packets\n"
                        )

                if host["top_dns_queries"]:
                    txt_file.write("Top DNS queries:\n")
                    for domain in host["top_dns_queries"][:5]:
                        txt_file.write(
                            f"  - {domain['domain']}: "
                            f"{domain['queries']} queries\n"
                        )

                txt_file.write("\n")

            if hidden_normal_count > 0:
                txt_file.write(
                    f"{hidden_normal_count} additional likely-normal "
                    "host(s) are available in the full JSON report data.\n\n"
                )

            txt_file.write(
                "AUTOMATED EXPLANATION\n"
            )

            txt_file.write(
                "=====================\n"
            )

            for line in explanation_lines:
                txt_file.write(
                    f"{line}\n"
                )

            txt_file.write("\n")

            txt_file.write(
                "Important: Findings represent behavioral "
                "indicators and should be validated with "
                "additional security context before drawing "
                "final conclusions.\n"
            )

            if ai_explanation:
                txt_file.write("\n")
                txt_file.write(
                    "AI ANALYST EXPLANATION\n"
                )
                txt_file.write(
                    "======================\n"
                )
                txt_file.write(
                    ai_explanation + "\n"
                )


        print("\nReport Export:")
        print("==============")

        print(
            f"TXT report saved to:\n  {txt_report_path}"
        )

        print(
            f"\nJSON report saved to:\n  {json_report_path}"
        )

        report_data["report_export"] = {
            "saved": True,
            "txt_path": txt_report_path,
            "json_path": json_report_path
        }

    else:
        print("\nReport Export:")
        print("==============")
        print("Report files were not saved.")

        report_data["report_export"] = {
            "saved": False,
            "txt_path": None,
            "json_path": None
        }

    print("\n==========================================")
    print("Analysis finished.")
    print("==========================================")

    return report_data


def main():
    while True:
        print("\n==========================================")
        print("       AI PCAP Security Analyzer")
        print(f"              Version {VERSION}")
        print("==========================================")
        print("\n1. Analyze a PCAP file")
        print("2. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            print()
            analyze_pcap()

            while True:
                print("\n1. Analyze another PCAP")
                print("2. Exit")
                next_choice = input("\nSelect an option: ").strip()

                if next_choice == "1":
                    break
                elif next_choice == "2":
                    print("\nExiting AI PCAP Security Analyzer.")
                    return
                else:
                    print("\nInvalid option. Enter 1 or 2.")

        elif choice == "2":
            print("\nExiting AI PCAP Security Analyzer.")
            return
        else:
            print("\nInvalid option. Enter 1 or 2.")


if __name__ == "__main__":
    main()